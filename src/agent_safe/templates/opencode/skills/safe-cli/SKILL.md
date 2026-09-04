---
name: safe-cli
description: Использование кроссплатформенного CLI safe вместо прямых рискованных команд.
compatibility: opencode
---

# safe CLI

Используй `safe` для любых действий, меняющих внешнее состояние.

## Жизненный цикл файлов и каталогов

Для обычных данных используй обратимый `safe fs-trash`. Для данных, которые действительно являются расходными, сначала явно зафиксируй их класс, затем выполняй окончательную очистку только через `safe`:

```bash
safe fs-mark PATH --class temporary --reason "временные данные задачи"
safe fs-status PATH
safe fs-cleanup PATH --reason "задача завершена, временные данные больше не нужны"
```

Классы ресурсов:

- `normal` — значение по умолчанию; необратимая очистка запрещена;
- `temporary` — объект явно признан временным; `fs-cleanup` разрешён;
- `protected` — объект явно отмечен как требующий сохранения; `fs-cleanup` запрещён.

`fs-mark` допускается и для уже существующего объекта, в том числе для конкретного объекта внутри `.agent-safety/trash`. Класс следует за записанным `fs-move`/`fs-trash`, поэтому заранее помеченный временный объект можно сначала убрать обратимо, а затем окончательно очистить в trash.

`fs-cleanup` — необратимая операция. До удаления `safe` пишет в journal intent с точным путём, классом и снимком объекта; после удаления пишет tombstone с результатом verify. Если удаление завершилось неожиданно или частично, включается Recovery Mode. Не заменяй этот протокол прямым `rm`, `Remove-Item`, `rmdir` или другим каналом.

Для `exec-risky`, `system-change`, `yc-change` и `ssh-relay-risky` expected state должен иметь структуру:

```json
{
  "assertions": {
    "state": "expected"
  },
  "declarations": {
    "operation": "update"
  }
}
```

`assertions` — свойства, которые verify обязан подтвердить. `declarations` — контекст, который сохраняется в журнале, но не считается проверенным.

Verify-команда должна вывести один JSON-объект фактического состояния. Все assertions должны присутствовать с теми же типами и значениями. Дополнительные поля допустимы.

```bash
safe exec-risky \
  --channel unknown \
  --domain unknown \
  --target "exact target" \
  --reason "approved change" \
  --expected-state '{"assertions":{"ok":true},"declarations":{"operation":"apply"}}' \
  --rollback-command "exact rollback" \
  --verify-command "command that prints {\"ok\":true}" \
  --approved \
  -- command args
```

Непустые assertions без verify запрещены. При отсутствующем поле, несовпадении значения или типа, невалидном JSON либо ошибке verify транзакция получает `unexpected`, включается Recovery Mode, а receipt не запускается.

Для PowerShell предпочитай `--expected-state-file`, `--rollback-command-file`, `--verify-command-file` и `--receipt-command-file`, чтобы не усложнять вложенное quoting.

## Длительные операции и ssh_relay job

Запуск длительной операции не равен её завершению.

Для lifecycle job должны существовать стабильные `correlation_id` и `event_id`. Одно имя `--job` не является достаточным ID запуска: после terminal state оно может использоваться повторно.

Правила:

1. До `job start` определить exact target, expected state и rollback/recovery plan.
2. Успешный launcher означает только `started`, но не `completed`/`done`.
3. Финальный `completed` допустим только после доказанного `exit_code=0`.
4. После `completed` всё равно выполнить verify заранее заданного expected state.
5. Доказанный ненулевой exit code означает `failed` и требует Recovery Mode для risky-операции.
6. `stopped` не считается успехом исходной операции: target мог измениться частично.
7. Timeout/disconnect или иное `unknown` нельзя автоматически превращать в success/failure и нельзя лечить повторным `job start`.
8. После reconnect сначала выполнить read-only `job status`/`job list`, сверить `job` + `correlation_id` и только затем продолжать аудит.
9. Повторная доставка lifecycle receipt обязана использовать прежний `event_id`; одинаковый `event_id` — одно логическое событие.

`ssh_relay 0.7.0` ещё не поддерживает `job start --risky`/lifecycle receipts. Не оборачивай его `job start` в существующий синхронный `safe ssh-relay-risky` как замену: нулевой код wrapper может создать ложный финальный успех. Для high-risk long-job требуются lifecycle-гарантии из `docs/ASYNC_JOBS.md` либо явный ручной safety/recovery процесс до появления совместимой версии relay.

Не заменяй `safe fs-trash` или `safe fs-cleanup` прямым удалением и не обходи `safe` через shell, API или другой канал.
