---
name: safe-cli
description: Использование кроссплатформенного CLI safe вместо прямых рискованных команд.
compatibility: opencode
---

# safe CLI

Используй `safe` для любых действий, меняющих внешнее состояние.

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

Не заменяй `safe fs-trash` прямым удалением и не обходи `safe` через shell, API или другой канал.
