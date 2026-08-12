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
- пустой, невалидный или не являющийся объектом JSON фактического состояния;
- неизвестный результат длительной risky-операции после timeout/disconnect;
- потеря подтверждения `job start`/`job stop`, если удалённое действие могло уже начаться;
- конфликт lifecycle receipts с одинаковым `event_id`.

Правила:

1. Остановить исходную задачу.
2. Не выполнять cleanup, delete, overwrite, reset, force или слепой повтор.
3. Выполнять только read-only диагностику.
4. Сохранить команду, cwd, target, expected state, actual state, verified, missing и mismatched assertions.
5. Для длительной операции сохранить `job`, `correlation_id`, известные lifecycle events и terminal exit code, если он доказан.
6. После reconnect сначала восстановить состояние через read-only `job status`/`job list`; не повторять `job start` автоматически.
7. Установить причину расхождения.
8. Подготовить варианты восстановления.
9. Получить подтверждение перед любым новым изменением состояния.

Для long-job transport timeout/disconnect не является доказательством ни success, ни failure. `completed` допустим только при доказанном `exit_code=0`; `failed` — при доказанном ненулевом exit code. `stopped` не считается успешным завершением исходной risky-операции.

Используй `safe diagnose` и `safe recovery-plan`.
