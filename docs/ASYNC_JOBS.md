# Длительные асинхронные операции

Этот документ задаёт контракт `agent-safe` для длительных операций, которые запускаются отдельно и завершаются позже. Основной интеграционный сценарий — `ssh_relay 0.7.0` с командами `job start/status/tail/wait/stop/list`.

## Результат аудита

Текущий формат удалённых JSONL receipts менять не требуется.

`safe receipt-command` уже формирует append-only JSON-объект с полем `status` без жёсткого списка значений и допускает дополнительные поля через `--field`. Поэтому существующий формат способен представить отдельные события `started`, `completed`, `failed`, `stopped` и `unknown`, добавить идентификаторы job/correlation и terminal exit code. Старые записи `status=done` остаются валидными и не требуют миграции.

Ограничение находится не в формате receipt, а в семантике синхронного выполнения: успешное завершение wrapper-команды `job start` подтверждает только запуск механизма job и не доказывает результат длительной команды. Поэтому `job start` нельзя проводить через существующий `safe ssh-relay-risky` как обычную синхронную risky-команду: это могло бы создать ложный финальный `done`.

## Термины

- `job` — пользовательское имя задачи `ssh_relay`; в `0.7.0` оно может быть повторно использовано после terminal state и поэтому не является уникальным ID запуска.
- `correlation_id` — непрозрачный стабильный идентификатор одного конкретного запуска. Создаётся до `job start` и не переиспользуется для следующего запуска того же `job`.
- `event_id` — стабильный ключ одного lifecycle-события. Повторная доставка того же события обязана использовать тот же `event_id`.
- terminal state — доказанное завершение процесса: `completed`, `failed` либо `stopped`.
- transport success — успешный ответ локального/SSH transport. Он не является доказательством terminal state.

`correlation_id` не должен строиться из полной команды, секретов, токенов или иных чувствительных данных.

## Lifecycle receipt

Для длительного risky-job используются отдельные append-only события. Общие поля:

```json
{
  "timestamp_utc": "2026-08-12T12:00:00Z",
  "tool": "ssh_relay",
  "change": "long-job",
  "target": "host:exact-target",
  "status": "started",
  "job": "build-app",
  "correlation_id": "opaque-operation-id",
  "event_id": "opaque-operation-id:started"
}
```

Допустимые lifecycle-статусы:

- `started` — launcher подтверждён и `correlation_id` сохранён вместе с job-state;
- `completed` — длительная команда доказанно завершилась с `exit_code=0`;
- `failed` — длительная команда доказанно завершилась с ненулевым `exit_code`;
- `stopped` — задача доказанно остановлена по явному запросу;
- `unknown` — результат нельзя надёжно классифицировать по сохранённому состоянию.

Для terminal receipt обязательно поле `exit_code`, если код завершения известен. Для `completed` он должен быть равен `0`; для `failed` — ненулевым. `stopped` может содержать фактический код завершения, например результат SIGTERM/SIGKILL.

`event_id` является dedup-ключом. Повтор записи/доставки одного события не создаёт второй логический успех. Для разных стадий одного запуска используются разные `event_id`, но один `correlation_id`.

## Контракт с ssh_relay

### Текущее состояние 0.7.0

`ssh_relay 0.7.0` уже обеспечивает необходимые фактические состояния job:

- `running` — exit code отсутствует, PID и start time подтверждены;
- `succeeded` — сохранён `exit_code=0`;
- `failed` — сохранён ненулевой exit code;
- `unknown` — exit code отсутствует, а исходный процесс нельзя надёжно подтвердить.

`job start` в `0.7.0` намеренно не поддерживает `--risky` и не пишет lifecycle receipts. Это безопаснее, чем записывать `status=done` после успешного launcher.

Для полной интеграции с `agent-safe` следующая доработка `ssh_relay` должна поддержать стабильный `correlation_id` в job-state и lifecycle receipts. Предпочтительный интерфейс запуска:

```text
ssh_relay job start --risky --correlation-id <ID> --receipt-path <JSONL> --job <JOB> "COMMAND"
```

`job status` и `job list` должны возвращать сохранённый `correlation_id`, чтобы после reconnect можно было доказать, что найдено состояние именно запрошенного запуска, а не более старой/новой задачи с тем же именем.

### job start --risky

До запуска caller обязан определить target, expected state, rollback/recovery plan и создать `correlation_id`.

После того как remote launcher подтверждён и `correlation_id` устойчиво сохранён в job-state, `ssh_relay` пишет ровно одно логическое событие `started`. Успех `job start` означает только `started`, но никогда не `completed`/`done`.

Если управляющий ответ потерян после передачи запроса, caller не повторяет `job start`. Сначала выполняются только `job status`/`job list` и сверяется `correlation_id`.

### job status

`job status` является read-only источником фактического состояния. Сам по себе успешный transport response ничего не говорит об успехе job.

Соответствие состояний:

```text
running   -> terminal receipt отсутствует
succeeded -> completed, только при exit_code == 0
failed    -> failed, только при доказанном ненулевом exit_code
unknown   -> unknown; автоматический повтор job запрещён
```

Исчезновение PID без exit code не считается завершением.

### job completion / failed

Terminal lifecycle receipt должен формироваться на стороне, которая наблюдает сохранённый exit code, а не на основании успешного возврата wrapper-команды.

`completed` доказывает успешное завершение процесса, но не заменяет `agent-safe verify`. После `completed` агент обязан проверить заранее заданный expected state. Только успешный verify позволяет считать risky-операцию полностью успешной в локальном safety-журнале.

`failed` означает доказанный ненулевой exit code. Для risky-операции это unexpected result: исходная задача останавливается, выполняется read-only диагностика и готовится recovery plan.

### job stop

`job stop` — отдельное state-changing действие. Оно должно проверять тот же `job` + `correlation_id` и не искать процесс по тексту команды.

После доказанной остановки создаётся `stopped` event с тем же `correlation_id`. `stopped` не является успешным завершением исходной risky-операции: возможен частично изменённый target, поэтому требуется verify/recovery.

Если ответ `job stop` потерян, повторять stop вслепую нельзя. Сначала нужно восстановить состояние через `job status`.

### Потеря transport после start

Правило:

```text
transport timeout/disconnect != job failure != job success
```

Если неизвестно, был ли `job start` принят, локальный результат остаётся `unknown`. После reconnect выполняются только `job status`/`job list`. Новый запуск допустим только после доказательства, что предыдущий запуск не существует и не мог изменить target.

### Reconnect и восстановление аудита

После reconnect:

1. получить `job status`/`job list`;
2. сверить `job` и `correlation_id`;
3. прочитать terminal exit code, если он есть;
4. восстановить отсутствующее lifecycle-событие с тем же стабильным `event_id`;
5. не повторять исходную risky-команду;
6. после `completed` выполнить verify expected state;
7. после `failed`, `stopped` или `unknown` перейти к диагностике/recovery.

### Если terminal receipt временно не записан

Ошибка записи receipt не меняет фактический terminal state job и не разрешает повтор job.

`ssh_relay` должен сохранить достаточное terminal evidence (`correlation_id`, state, exit code и стабильный `event_id`) рядом с job-state и отметить аудит как незавершённый. При последующей явной reconciliation допускается повторная попытка записи **того же** lifecycle event с тем же `event_id`. Это не очередь выполнения задач и не повтор команды.

Пока terminal receipt не подтверждён, аудит считается неполным; `completed` нельзя повышать до полного локального safety-success без verify и подтверждения аудита.

## Deduplication

Минимальное правило потребителя JSONL:

```text
одинаковый event_id -> одно логическое событие
```

Если две записи с одним `event_id` имеют разные `status`, `correlation_id`, `job` или `exit_code`, это конфликт аудита и основание для Recovery Mode, а не повод выбрать более удобную запись.

Writer при retry обязан повторять исходный `event_id`, а не генерировать новый.

## Секреты

Lifecycle contract не добавляет необходимости сохранять полную команду.

В receipts/job-state запрещено добавлять:

- SSH/sudo пароли;
- session token;
- private keys;
- authorization headers;
- полную команду, если она может содержать секреты;
- необработанные stdout/stderr только ради correlation.

Для correlation используется непрозрачный ID, а не hash/копия секретного command text.

## Совместимость

Существующие JSONL receipts вида `status=done` остаются читаемыми. Новые поля являются дополнительными, существующие обязательные поля не переименовываются и не удаляются.

Синхронные `exec`/`sudo-exec` продолжают использовать прежний контракт. Lifecycle statuses применяются только к операциям, чей запуск и завершение разделены во времени.
