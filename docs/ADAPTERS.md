# Адаптеры

`agent-safe` использует единый протокол для любого изменения внешнего состояния:

```text
classify -> inspect -> expected_state -> checkpoint -> execute one atomic action -> verify -> continue/recovery
```

Адаптеры являются небольшими обёртками над каналами выполнения. Сравнение ожидаемого и фактического состояния централизовано в generic adapter; `system`, `yc` и `ssh_relay` не реализуют собственные алгоритмы проверки.

## Структурный expected state

Для рискованных команд expected state разделяется на проверяемые утверждения и декларативный контекст:

```json
{
  "assertions": {
    "temporary_files_absent": true,
    "ssh_key_preserved": true
  },
  "declarations": {
    "operation": "cleanup"
  }
}
```

Verify-команда должна завершиться с кодом `0` и вывести один JSON-объект фактического состояния:

```json
{
  "temporary_files_absent": true,
  "ssh_key_preserved": true,
  "diagnostics": {}
}
```

Правила проверки:

- все поля `assertions` обязательны;
- типы и значения должны совпадать точно;
- вложенные объекты и списки сравниваются рекурсивно;
- дополнительные поля фактического состояния допустимы;
- `declarations` сохраняются в журнале, но не помечаются как проверенные;
- непустые `assertions` требуют verify-команду;
- невалидный JSON, отсутствующее поле, несовпадение значения или типа дают `unexpected` и включают Recovery Mode;
- receipt запускается только после полного подтверждения assertions.

В журнале сохраняются `verification_complete`, `verified_assertions`, `missing_assertions`, `mismatched_assertions` и `actual_state`. Старые записи читаются без миграции.

## Универсальный адаптер выполнения

Read-only команда:

```bash
safe exec-readonly --channel local --domain system -- python --version
```

Рискованная команда:

```bash
safe exec-risky \
  --channel local \
  --domain unknown \
  --target "resource:exact-id-or-path" \
  --reason "обоснование изменения" \
  --expected-state '{"assertions":{"state":"expected"},"declarations":{"operation":"update"}}' \
  --rollback-command "точная команда отката" \
  --verify-command "команда, печатающая JSON фактического состояния" \
  --approved \
  -- command arg1 arg2
```

`exec-risky` отказывается работать без точной цели, причины, expected state, rollback и подтверждения. Если assertions непусты, verify обязателен. Ненулевой код основной или проверочной команды, неполная проверка и несовпадение переводят транзакцию в `unexpected` и создают `.agent-safety/INCIDENT_BLOCKED`.

## Git adapter

Создание evidence перед рискованной работой:

```bash
safe git-checkpoint --reason "before rebase" --bundle
```

Предпросмотр очистки без удаления:

```bash
safe git-clean-preview
safe git-clean-preview --include-ignored
```

Прямые `git clean -f`, `git reset --hard`, force push и удаление веток должны блокироваться OpenCode permissions либо выполняться через специализированный безопасный сценарий.

## ssh_relay adapter

Адаптер ожидает relay-интерфейс:

```text
<relay command> exec "<remote command>"
```

Read-only команда:

```bash
safe ssh-relay-readonly \
  --relay "ssh_relay" \
  --host-label "4BSDownloader2" \
  --remote-command "pwd" \
  --reason "проверить удалённый рабочий каталог"
```

Рискованная команда:

```bash
safe ssh-relay-risky \
  --relay "ssh_relay" \
  --host-label "server-1" \
  --remote-command "systemctl restart app" \
  --reason "перезапуск после согласованного изменения" \
  --expected-state '{"assertions":{"service":"active"},"declarations":{"operation":"restart"}}' \
  --rollback-command "ssh_relay exec 'systemctl restart app-old'" \
  --verify-remote-command "команда, печатающая {\"service\":\"active\"}" \
  --approved
```

Удалённая verify-команда должна вернуть JSON. Сравнение выполняется generic adapter после получения stdout relay-команды.

## Yandex Cloud adapter

Read-only проверка:

```bash
safe yc-readonly -- config list
safe yc-readonly -- compute instance get --id <instance-id>
safe yc-readonly -- compute disk list
```

Изменение облачного ресурса:

```bash
safe yc-change \
  --target "compute.instance:<id>" \
  --reason "остановить тестовую ВМ" \
  --expected-state '{"assertions":{"status":"STOPPED"},"declarations":{"operation":"stop"}}' \
  --rollback-command "yc compute instance start --id <id>" \
  --verify-command "команда, печатающая нормализованный JSON фактического состояния" \
  --approved \
  -- compute instance stop --id <id>
```

Удаление ресурсов, изменение IAM, сети, security groups, дисков, публичных IP и production-ВМ остаются критическими действиями.

## System / VM adapter

Read-only проверка:

```bash
safe system-readonly -- hostname
safe system-readonly -- systemctl status app
```

Рискованное системное действие:

```bash
safe system-change \
  --target "service:app" \
  --reason "перезапуск после согласованного изменения" \
  --expected-state '{"assertions":{"service":"active"},"declarations":{"operation":"restart"}}' \
  --rollback-command "systemctl restart app-old" \
  --verify-command "команда, печатающая {\"service\":\"active\"}" \
  --approved \
  -- systemctl restart app
```

При unexpected нельзя повторять действие вслепую. Следует использовать `safe diagnose` и `safe recovery-plan`.

## Неизвестные системы

Для инструмента без отдельного адаптера:

1. Выполнить `safe assess --command "..."`.
2. Использовать только help/status/list/show/describe/plan/dry-run/diff.
3. Применять `safe exec-readonly` только к доказанно read-only командам.
4. Любое изменение или неясную команду проводить через `safe exec-risky`.
5. Не выполнять действие, если последствия, assertions или rollback не определены.
