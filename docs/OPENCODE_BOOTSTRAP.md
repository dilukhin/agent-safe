# OpenCode bootstrap

`safe opencode-bootstrap` подключает agent-safe к OpenCode без ручного копирования файлов.

Команда умеет:

- создать или обновить `opencode.json` с осторожными permissions;
- скопировать agent-safe skills;
- добавить короткий блок Agent Safety в `AGENTS.md`;
- сначала показать diff через `--dry-run`;
- перед изменениями сделать backup существующих файлов;
- записать операцию в `.agent-safety/actions.jsonl`.

## Глобальное подключение

Linux/macOS/Termux:

```bash
safe opencode-bootstrap --scope global --dry-run
safe opencode-bootstrap --scope global --apply
```

Windows:

```powershell
safe opencode-bootstrap --scope global --dry-run
safe opencode-bootstrap --scope global --apply
```

По умолчанию global scope использует:

```text
~/.config/opencode/opencode.json
~/.config/opencode/skills/
~/.config/opencode/AGENTS.md
```

Путь можно переопределить переменной `OPENCODE_CONFIG_DIR` или аргументом `--opencode-dir`.

## Проектное подключение

Из корня проекта:

```bash
safe opencode-bootstrap --scope project --dry-run
safe opencode-bootstrap --scope project --apply
```

Project scope использует:

```text
<project>/opencode.json
<project>/.opencode/skills/
<project>/AGENTS.md
```

## Частичное подключение

```bash
safe opencode-bootstrap --scope global --apply --no-agents
safe opencode-bootstrap --scope global --apply --no-config
safe opencode-bootstrap --scope global --apply --no-skills
```

## Пользовательские пути

```bash
safe opencode-bootstrap \
  --scope global \
  --dry-run \
  --config-path ~/.config/opencode/opencode.json \
  --skills-dir ~/.config/opencode/skills \
  --agents-path ~/.config/opencode/AGENTS.md
```

## Безопасность

`--dry-run` ничего не меняет, а только показывает план и unified diff.

`--apply` перед изменением существующих файлов сохраняет backup в:

```text
.agent-safety/snapshots/opencode-bootstrap-*/
```

После `--apply` создаётся запись `opencode.bootstrap` в журнале действий.

## Что делать после bootstrap

Проверить:

```bash
safe status
safe assess --command "rm -rf build"
```

Затем перезапустить OpenCode-сессию, чтобы агент увидел новые skills, permissions и `AGENTS.md`.
