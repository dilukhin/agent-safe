# agent-safe

**agent-safe** — кроссплатформенный safety runtime для CLI/AI-агентов. Проект добавляет предохранительный слой между агентом и командами, которые меняют внешнее состояние: локальные файлы, git, удалённые машины, облачные ресурсы, виртуальные машины, системные сервисы и заранее неизвестные инструменты.

Главная идея: агент не должен напрямую выполнять опасные команды вроде `rm -rf`, `Remove-Item -Recurse`, `git clean -f`, `yc ... delete`, `curl | sh` или удалённые destructive-команды через SSH. Вместо этого он должен проходить универсальный протокол безопасности через CLI `safe`:

```text
classify → inspect → expected_state → checkpoint → execute one atomic action → verify → continue/recovery
```

Если после опасного действия результат отличается от ожидаемого, это считается инцидентом, а не обычным препятствием. Основная задача останавливается, дальнейшие опасные действия блокируются, разрешены только read-only диагностика и план восстановления.

## Зачем это нужно

AI-агенты и CLI-ассистенты хорошо автоматизируют рутинные действия, но иногда:

- неверно понимают последствия команды;
- выполняют действие в не той директории, среде или машине;
- используют опасные флаги вроде `--force`, `-Recurse`, `-Confirm:$false`;
- продолжают работу после неожиданного результата;
- пытаются «починить» ситуацию новой destructive-командой;
- работают с неизвестным инструментом так, будто он безопасен.

`agent-safe` решает эту проблему не длинным промптом, а техническим протоколом: риск оценивается до выполнения, действие журналируется, ожидаемое состояние фиксируется заранее, а unexpected result переводит систему в Recovery Mode.

## Что умеет текущая версия

Реализовано в MVP:

- универсальная оценка риска команд;
- консервативная политика для неизвестных инструментов и подсистем;
- append-only журнал действий `.agent-safety/actions.jsonl`;
- recovery lock через `.agent-safety/INCIDENT_BLOCKED`;
- checkpoint проекта перед рискованными действиями;
- обратимые файловые операции `fs-move` и `fs-trash`;
- `undo` / `redo` для записанных обратимых операций;
- generic adapter для read-only и risky shell-команд;
- git adapter: checkpoint, bundle, безопасный preview `git clean`;
- ssh_relay adapter для удалённых read-only и risky-команд;
- Yandex Cloud adapter для `yc` read-only и change-операций;
- system/VM adapter для системных команд и операций с сервисами;
- пример OpenCode permissions;
- OpenCode skills, которые можно загружать on demand;
- тесты на Python `unittest` без внешних зависимостей.

Планируемые направления:

- адаптеры для БД и миграций;
- адаптер для secrets/credentials;
- более богатая верификация облачных и сетевых ресурсов;
- политики для production/dev/test окружений;
- дополнительные сценарии regression-тестов на агентские инциденты.

## Поддерживаемые платформы

Проект написан на Python и использует только стандартную библиотеку.

Целевые платформы:

- Windows;
- Linux;
- macOS;
- Android через Termux.

Минимальная версия Python: **3.10**.

## Установка

### Из исходников

```bash
git clone <repo-url> agent-safe
cd agent-safe
python -m pip install -e .
safe --help
```

### Без установки, через модуль Python

Так как проект использует `src/` layout, без установки нужно добавить `src` в `PYTHONPATH`.

Linux/macOS/Termux:

```bash
cd agent-safe
PYTHONPATH=src python -m agent_safe --help
```

Windows PowerShell:

```powershell
cd agent-safe
$env:PYTHONPATH = "src"
python -m agent_safe --help
```

### Портативный zipapp

Сборка:

```bash
python scripts/build_zipapp.py
python dist/safe.pyz --help
```

Файл `dist/safe.pyz` можно переносить между Windows, Linux, macOS и Android/Termux, если на целевой системе есть совместимый Python.

### Android / Termux

```bash
pkg install python git
cd agent-safe
python -m pip install -e .
safe --help
```

## Быстрый старт

Оценить риск команды:

```bash
safe assess --command "rm -rf build"
```

Создать checkpoint перед рискованной работой:

```bash
safe checkpoint --reason "before risky refactor"
```

Безопасно переместить файл или директорию:

```bash
safe fs-move ./old ./new --reason "rename directory"
```

Безопасно «удалить» объект через перемещение в trash:

```bash
safe fs-trash ./tmp-file --reason "remove temporary file safely"
```

Сделать git checkpoint перед рискованной git-операцией:

```bash
safe git-checkpoint --reason "before rebase" --bundle
```

Предпросмотр git clean без удаления:

```bash
safe git-clean-preview
safe git-clean-preview --include-ignored
```

Выполнить read-only команду через универсальный адаптер:

```bash
safe exec-readonly --channel local --domain system -- python --version
```

Выполнить рискованную команду только с явным target, expected state, rollback и verify:

```bash
safe exec-risky \
  --channel local \
  --domain unknown \
  --target "resource:exact-id-or-path" \
  --reason "approved state change" \
  --expected-state '{"state":"expected"}' \
  --rollback-command "exact rollback command" \
  --verify-command "exact verification command" \
  --approved \
  -- command arg1 arg2
```

Посмотреть состояние safety-журнала:

```bash
safe status
```

Откатить последнюю обратимую операцию:

```bash
safe undo last
```

Повторить отменённую операцию:

```bash
safe redo last
```

Диагностика после unexpected result:

```bash
safe diagnose
safe recovery-plan
```

## Модель безопасности

### 1. Опасно всё, что меняет внешнее состояние

Команда считается потенциально рискованной, если она:

- создаёт, изменяет, перемещает или удаляет файлы;
- меняет git-историю или рабочее дерево;
- запускает, останавливает или перезапускает сервисы;
- меняет настройки ОС, registry, firewall, маршруты, DNS, VPN;
- меняет облачные ресурсы, диски, IP, IAM, security groups;
- выполняет действия на удалённой машине;
- выполняет миграции или изменения в БД;
- меняет секреты, ключи, токены, credentials;
- деплоит, публикует, пушит, применяет конфиги;
- использует неизвестный инструмент с неясными последствиями.

### 2. Неизвестная подсистема не считается безопасной

Если агент не знает команду, CLI, API или подсистему, `agent-safe` исходит из консервативного правила:

```text
unknown command + external state = high risk
unknown consequences + high risk = stop
unexpected result + high risk = recovery mode
```

Для неизвестных инструментов сначала допускаются только discovery/read-only действия: `help`, `version`, `status`, `list`, `show`, `describe`, `dry-run`, `plan`, `diff`.

### 3. Опасное действие должно быть предсказуемым

Для high-risk операций нужны:

- точный target;
- понятный channel;
- понятное окружение;
- причина действия;
- expected state до выполнения;
- rollback-команда или recovery-план;
- verify-команда;
- явное подтверждение `--approved`.

Нельзя полагаться на glob, aliases, hidden defaults, chained commands и «примерное понимание» поведения инструмента.

### 4. Unexpected result — это инцидент

Если verify не совпал с `expected_state` или risky-команда завершилась неожиданно:

- транзакция получает статус `unexpected`;
- создаётся `.agent-safety/INCIDENT_BLOCKED`;
- дальнейшие high-risk операции блокируются;
- основная задача должна остановиться;
- разрешены только диагностика и планирование восстановления.

Это правило защищает от самой опасной цепочки: «первая команда дала неожиданный результат, агент продолжил и сделал ещё хуже».

## Структура `.agent-safety`

В рабочем проекте `safe` создаёт служебную директорию:

```text
.agent-safety/
  actions.jsonl
  INCIDENT_BLOCKED
  checkpoints/
  command-output/
  evidence/
  recovery/
  trash/
```

Назначение:

- `actions.jsonl` — append-only журнал действий;
- `INCIDENT_BLOCKED` — флаг блокировки после unexpected result;
- `checkpoints/` — снимки состояния проекта;
- `command-output/` — stdout/stderr выполненных команд;
- `recovery/` — материалы для анализа и восстановления;
- `trash/` — безопасная замена прямому удалению.

## Журнал действий

Каждое значимое действие записывается как транзакция.

Пример полей:

```json
{
  "txn_id": "20260629-001",
  "domain": "filesystem",
  "channel": "local",
  "operation": "move",
  "risk": "dangerous",
  "target": "./old -> ./new",
  "reason": "rename directory",
  "expected_state": {
    "source_exists": false,
    "destination_exists": true
  },
  "undo": {
    "command": "move ./new ./old"
  },
  "redo": {
    "command": "move ./old ./new"
  },
  "status": "done"
}
```

Модель не должна писать журнал вручную. Его формирует `safe`.

## Адаптеры

### Generic execution adapter

Для неизвестных или ещё не поддержанных подсистем.

Read-only:

```bash
safe exec-readonly --channel local --domain unknown -- tool status
```

Risky:

```bash
safe exec-risky \
  --channel unknown \
  --domain unknown \
  --target "exact target" \
  --reason "why this is needed" \
  --expected-state '{"ok":true}' \
  --rollback-command "exact rollback" \
  --verify-command "exact verify" \
  --approved \
  -- tool apply --id exact-id
```

### Filesystem adapter

Используется для обратимых локальных операций.

```bash
safe fs-move ./source ./dest --reason "move safely"
safe fs-trash ./path --reason "remove safely"
safe undo last
safe redo last
```

Прямое удаление заменяется перемещением в `.agent-safety/trash/`.

### Git adapter

```bash
safe git-checkpoint --reason "before risky git operation" --bundle
safe git-clean-preview
```

`git-checkpoint` сохраняет evidence: `status`, `diff`, staged diff, последние коммиты. При `--bundle` создаётся git bundle.

Опасные команды вроде `git reset --hard`, `git clean -f`, `git branch -D`, `git push --force` не должны выполняться напрямую агентом.

### ssh_relay adapter

Для команд на удалённой машине через relay-интерфейс вида:

```text
<relay command> exec "<remote command>"
```

Read-only:

```bash
safe ssh-relay-readonly \
  --relay "ssh_relay" \
  --host-label "server-1" \
  --remote-command "pwd" \
  --reason "confirm remote cwd"
```

Risky:

```bash
safe ssh-relay-risky \
  --relay "ssh_relay" \
  --host-label "server-1" \
  --remote-command "systemctl restart app" \
  --reason "restart after approved config change" \
  --expected-state '{"service":"active"}' \
  --rollback-command "ssh_relay exec 'systemctl restart app-old'" \
  --verify-remote-command "systemctl is-active app" \
  --approved
```

Для удалённых команд особенно важно явно понимать host, user, cwd, окружение и blast radius.

### Yandex Cloud adapter

Read-only:

```bash
safe yc-readonly -- config list
safe yc-readonly -- compute instance get --id <instance-id>
safe yc-readonly -- compute disk list
```

State-changing:

```bash
safe yc-change \
  --target "compute.instance:<id>" \
  --reason "stop test VM" \
  --expected-state '{"status":"STOPPED"}' \
  --rollback-command "yc compute instance start --id <id>" \
  --verify-command "yc compute instance get --id <id>" \
  --approved \
  -- compute instance stop --id <id>
```

Критичными считаются удаление ресурсов, изменение IAM, security groups, сетевых маршрутов, публичных IP, дисков и snapshots.

### System / VM adapter

Read-only:

```bash
safe system-readonly -- hostname
safe system-readonly -- systemctl status app
```

Risky:

```bash
safe system-change \
  --target "service:app" \
  --reason "restart service after approved change" \
  --expected-state '{"service":"active"}' \
  --rollback-command "systemctl restart app-old" \
  --verify-command "systemctl is-active app" \
  --approved \
  -- systemctl restart app
```

Если сервис не поднялся после restart, нельзя «пробовать ещё что-нибудь». Нужно перейти в Recovery Mode.

## Recovery Mode

Recovery Mode включается, когда high-risk действие дало неожиданный результат.

Команды:

```bash
safe status
safe diagnose
safe recovery-plan
safe undo last
```

Разрешённый стиль работы:

1. остановить исходную задачу;
2. собрать read-only evidence;
3. сравнить expected state и actual state;
4. определить, можно ли безопасно выполнить undo;
5. если undo небезопасен — подготовить manual recovery plan;
6. получить подтверждение пользователя;
7. только после этого выполнять восстановление.

Не разрешено:

- cleanup;
- delete/remove;
- overwrite;
- reset/force;
- blind retry;
- продолжение исходной задачи.

Снять блокировку можно только после ручного анализа:

```bash
safe clear-block --reason "manual recovery completed and verified"
```

## Интеграция с OpenCode

Проект содержит пример конфигурации:

```text
opencode/opencode.json
opencode/skills/
```

Рекомендуемый подход:

- в `AGENTS.md` держать только короткое правило Universal Action Safety;
- подробные инструкции хранить в OpenCode skills;
- опасные прямые команды запрещать через permissions;
- разрешать read-only команды;
- risky-действия выполнять только через `safe`.

Пример короткого правила для `AGENTS.md`:

```md
## Universal Action Safety

Any command/tool/API call that changes external state is risky, regardless of channel: local shell, remote shell, ssh_relay, cloud CLI, VM, git, database, registry, service, network, package manager, secrets, or unknown subsystem.

Before any non-read-only action: classify risk, identify exact target and environment, define expected_state, prepare checkpoint/rollback, execute one atomic action, verify actual state.

If the tool or subsystem is unfamiliar, treat it as high-risk until proven otherwise. Use read-only discovery first.

Use the cross-platform `safe` CLI for risky actions. Do not call direct destructive commands.

If the actual result differs from expected_state, stop the original task immediately and enter Recovery Mode.
```

## Разработка

Запуск тестов после `pip install -e .`:

```bash
python -m unittest discover -s tests
```

Запуск тестов без установки:

```bash
PYTHONPATH=src python -m unittest discover -s tests
```

Сборка zipapp:

```bash
python scripts/build_zipapp.py
```

Проверка CLI из исходников без установки:

```bash
PYTHONPATH=src python -m agent_safe --help
PYTHONPATH=src python -m agent_safe assess --command "git clean -f"
```

Установка в editable-режиме:

```bash
python -m pip install -e .
```

## Структура проекта

```text
agent-safe/
  src/agent_safe/
    cli.py
    core/
      checkpoint.py
      journal.py
      models.py
      risk.py
    adapters/
      exec_adapter.py
      fs.py
      git.py
      ssh_relay.py
      system.py
      yc.py
  tests/
  docs/
    ADAPTERS.md
    DEPLOY.md
    UNIVERSAL_ACTION_SAFETY.md
  opencode/
    opencode.json
    skills/
  scripts/
    build_zipapp.py
    install_posix.sh
    install_windows.ps1
  AGENTS.md
  README.md
  pyproject.toml
```

## Дизайн-принципы

### Prompt is not enough

Промпт и `AGENTS.md` полезны, но они не должны быть единственной защитой. Агент может забыть правило, неправильно понять команду или продолжить после ошибки. Поэтому `agent-safe` добавляет технический runtime.

### Unknown is dangerous

Если инструмент неизвестен, нельзя считать его безопасным. Сначала read-only discovery, потом risk assessment, и только затем state-changing действие.

### One atomic action

Одна risky-команда — одна транзакция. Нельзя объединять `move`, `delete`, `cleanup`, `restart`, `verify` и «починку» в одну строку.

### Expected state before execution

Агент должен знать, что именно должно измениться. Если ожидаемое состояние нельзя сформулировать, команду выполнять нельзя.

### Stop on surprise

Неожиданный результат после опасного действия — это инцидент. Исходная задача останавливается.

### Recovery first

После unexpected result цель уже не «доделать задачу», а восстановить безопасное состояние.

## Ограничения текущей версии

- `agent-safe` не является sandbox и не может физически запретить все возможные обходы вне настроек агента/permissions.
- Denylist опасных команд не должен считаться полной защитой.
- Для некоторых доменов rollback пока описывается вручную.
- Адаптеры `yc`, `ssh_relay`, `system` пока являются safety-wrapper-слоем, а не полноценной моделью всех ресурсов.
- Для production-инфраструктуры нужны дополнительные политики доступа, snapshots, backups и отдельные роли.

## Лицензия

MIT.
