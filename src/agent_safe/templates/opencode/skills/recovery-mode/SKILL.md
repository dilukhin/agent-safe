---
name: recovery-mode
description: Порядок действий после unexpected результата высокорисковой операции.
compatibility: opencode
---

# Recovery Mode

Unexpected result после высокорискового действия — инцидент, а не обычное препятствие.

К unexpected относятся:

- ненулевой код основной или verify-команды;
- отсутствующее assertion;
- несовпадение значения;
- несовпадение типа;
- пустой, невалидный или не являющийся объектом JSON фактического состояния.

Правила:

1. Остановить исходную задачу.
2. Не выполнять cleanup, delete, overwrite, reset, force или слепой повтор.
3. Выполнять только read-only диагностику.
4. Сохранить команду, cwd, target, expected state, actual state, verified, missing и mismatched assertions.
5. Установить причину расхождения.
6. Подготовить варианты восстановления.
7. Получить подтверждение перед любым новым изменением состояния.

Используй `safe diagnose` и `safe recovery-plan`.
