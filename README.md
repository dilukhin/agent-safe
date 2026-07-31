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
- структурная проверка `expected_state.assertions` по JSON, возвращённому verify-командой;
- git adapter: checkpoint, bundle, безопасный preview `git clean`;
- ssh_relay adapter для удалённых read-only и risky-команд;
- Yandex Cloud adapter для `yc` read-only и change-операций;
- system/VM adapter для системных команд и операций с сервисами;
- пример OpenCode permissions;
- OpenCode skills, которые можно загружать on demand;
- `safe opencode-bootstrap` для автоматического подключения к OpenCode;
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
git clone https://github.com/dilukhin/agent-safe.git agent-safe
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
  --expected-state '{"assertions":{"state":"expected"},"declarations":{"operation":"update"}}' \
  --rollback-command "exact rollback command" \
  --verify-command "command that prints {\"state\":\"expected\"}" \
  --receipt-command "optional command that records the completed change on the target side" \
  --approved \
  -- command arg1 arg2
```

`assertions` содержат только свойства, которые verify обязан подтвердить. `declarations` сохраняются как контекст, но не считаются проверенными. Verify-команда должна вывести один JSON-объект фактического состояния. Все assertions должны присутствовать с теми же типами и значениями; дополнительные поля допустимы.

Отсутствующее поле, несовпадение значения или типа, пустой либо невалидный JSON и ненулевой код verify дают `unexpected` и включают Recovery Mode. Непустые assertions без verify-команды запрещены до выполнения основного действия.

On Windows/PowerShell, prefer file arguments for JSON and nested commands:

```powershell
safe exec-risky `
  --channel remote `
  --domain system `
  --target "host:path-or-resource" `
  --reason "approved remote change" `
  --expected-state-file .\expected-state.json `
  --rollback-command-file .\rollback.txt `
  --verify-command-file .\verify.txt `
  --receipt-command-file .\receipt.txt `
  --approved `
  -- command arg1 arg2
```

`expected-state.json` должен содержать объект с полями `assertions` и `declarations`. Файл verify-команды должен описывать команду, которая печатает JSON фактического состояния.

`--receipt-command` runs only after the main command succeeds and all assertions are fully verified. It is not run after an incomplete or failed verification. Use it to write an audit receipt on the changed host, for example append JSONL to `C:\ProgramData\agent-safe\changes.jsonl` during remote maintenance.

Generate a receipt command instead of hand-writing nested quoting:

```bash
safe receipt-command \
  --format posix \
  --path ~/.local/state/agent-safe/changes.jsonl \
  --change "install package" \
  --target "host:prod" \
  --field package=nginx > receipt.txt
```

For Linux hosts via `ssh_relay`, store the receipt on the remote host with `--receipt-path`:

```bash
safe ssh-relay-risky \
  --relay "py ssh_relay.py" \
  --relay-name prod \
  --host-label prod \
  --remote-command "sudo -n apt-get install -y nginx" \
  --expected-state-file expected-state.json \
  --rollback-command-file rollback.txt \
  --verify-remote-command "command that prints normalized JSON" \
  --receipt-path ~/.local/state/agent-safe/changes.jsonl \
  --approved
```

`ssh-relay-risky` passes `--risky` to compatible `ssh_relay.py`, so the relay writes the remote receipt after the command succeeds. `--receipt-remote-command` remains available for older/custom transports or additional audit actions.

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

## Подключение к OpenCode одной командой

После установки `safe` можно подключить agent-safe к OpenCode без ручного копирования skills и config.

Сначала dry-run:

```bash
safe opencode-bootstrap --scope global --dry-run
```

Если diff выглядит нормально, применить:

```bash
safe opencode-bootstrap --scope global --apply
```

Для проектной установки из корня репозитория:

```bash
safe opencode-bootstrap --scope project --dry-run
safe opencode-bootstrap --scope project --apply
```

Команда делает три вещи:

- создаёт/обновляет `opencode.json` с осторожными permissions;
- копирует agent-safe skills;
- добавляет короткий блок Agent Safety в `AGENTS.md`.

`--dry-run` ничего не меняет. `--apply` перед изменениями делает backup существующих файлов в `.agent-safety/snapshots/` и записывает транзакцию `opencode.bootstrap` в журнал только если были реальные изменения.

Подробности: [`docs/OPENCODE_BOOTSTRAP.md`](docs/OPENCODE_BOOTSTRAP.md).

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
- expected state с проверяемыми assertions до выполнения;
- rollback-команда или recovery-план;
- verify-команда, возвращающая JSON фактического состояния;
- явное подтверждение `--approved`.

Нельзя полагаться на glob, aliases, hidden defaults, chained commands и «примерное понимание» поведения инструмента.

### 4. Unexpected result — это инцидент

Если verify не подтвердил все assertions или risky-команда завершилась неожиданно:

- транзакция получает статус `unexpected`;
- создаётся `.agent-safety/INCIDENT_BLOCKED`;
- дальнейшие high-risk операции блокируются;
- основная задача должна остановиться;
- receipt не запускается;
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

Для рискованной команды журнал содержит ожидаемое состояние и структурный результат проверки:

```json
{
  "txn_id": "20260728-001",
  "status": "done",
  "expected_state": {
    "assertions": {
      "service": "active"
    },
    "declarations": {
      "operation": "restart"
    }
  },
  "verification_complete": true,
  "verified_assertions": {
    "service": "active"
  },
  "missing_assertions": {},
  "mismatched_assertions": {},
  "actual_state": {
    "service": "active",
    "diagnostics": {}
  }
}
```

Старые JSONL-записи остаются читаемыми и не требуют миграции. Модель не должна писать журнал вручную: его формирует `safe`.

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
  --expected-state '{"assertions":{"ok":true},"declarations":{"operation":"apply"}}' \
  --rollback-command "exact rollback" \
  --verify-command "command that prints {\"ok\":true}" \
  --approved \
  -- tool apply --id exact-id
```

Сравнение assertions с JSON из stdout verify централизовано в generic adapter. Тонкие адаптеры `system`, `yc` и `ssh_relay` не дублируют алгоритм.

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
  --expected-state '{"assertions":{"service":"active"},"declarations":{"operation":"restart"}}' \
  --rollback-command "ssh_relay exec 'systemctl restart app-old'" \
  --verify-remote-command "command that prints {\"service\":\"active\"}" \
  --approved
```

Для удалённых команд особенно важно явно понимать host, user, cwd, окружение и blast radius. Verify-команда должна печатать JSON фактического состояния; сравнение выполняет generic adapter.

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
  --expected-state '{"assertions":{"status":"STOPPED"},"declarations":{"operation":"stop"}}' \
  --rollback-command "yc compute instance start --id <id>" \
  --verify-command "command that prints normalized JSON with status" \
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
  --expected-state '{"assertions":{"service":"active"},"declarations":{"operation":"restart"}}' \
  --rollback-command "systemctl restart app-old" \
  --verify-command "command that prints {\"service\":\"active\"}" \
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
3. сравнить expected state, actual state, verified, missing и mismatched assertions;
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

Проект содержит пример конфигурации и встроенные шаблоны:

```text
opencode/opencode.json
opencode/skills/
src/agent_safe/templates/opencode/
```

Рекомендуемый способ подключения — команда bootstrap:

```bash
safe opencode-bootstrap --scope global --dry-run
safe opencode-bootstrap --scope global --apply
```

Для конкретного проекта:

```bash
safe opencode-bootstrap --scope project --dry-run
safe opencode-bootstrap --scope project --apply
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
PYTHONPATH=src python -m unittest discover -s tests -v
```

Сборка zipapp:

```bash
python scripts/build_zipapp.py
```

Проверка CLI из исходников без установки:

```bash
PYTHONPATH=src python -m agent_safe --help
PYTHONPATH=src python -m agent_safe assess --command "git clean -f"
PYTHONPATH=src python -m agent_safe opencode-bootstrap --scope project --dry-run
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
      verification.py
    adapters/
      exec_adapter.py
      fs.py
      git.py
      ssh_relay.py
      system.py
      yc.py
    templates/
      opencode/
        opencode.json
        skills/
    opencode_bootstrap.py
  tests/
  docs/
    ADAPTERS.md
    ANDROID_TERMUX_FINDINGS.md
    DEPLOY.md
    OPENCODE_BOOTSTRAP.md
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

Агент должен отделять проверяемые `assertions` от декларативного контекста. Непустые assertions требуют verify-команду, которая возвращает JSON фактического состояния. Если ожидаемое состояние нельзя сформулировать и проверить, команду выполнять нельзя.

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
