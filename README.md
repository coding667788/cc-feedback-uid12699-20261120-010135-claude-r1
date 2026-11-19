# 沙箱句柄继承与能力吊销的持久验证

离线、单机、只用 Python 3.12 标准库实现的沙箱能力检查服务。它把「进程 / 资源 /
逻辑句柄」这三类对象以及它们之间的授权关系存进 SQLite，在每次判定时**沿祖先链
逐跳重查**，给出可审计的结论：允许还是拒绝、被哪一跳阻断、那一跳的**确切代数**。

题面见 `task/PROMPT.txt`。运行环境：Windows 原生 Python 3.12，无第三方依赖，
不访问网络。

```
python -m solution --input cases.json --output result.json
python -m unittest discover -s tests -v
```

---

## 1. 规则

### 1.1 对象

| 对象 | 关键字段 | 代数的含义 |
| --- | --- | --- |
| 进程 `process` | `generation`（会话代数） | 每次 `restart_process` +1 |
| 资源 `resource` | `tenant`、`generation`、`rights` | 资源创建为 1，每次 `rebuild_resource` +1 |
| 沙箱 `sandbox` | 允许的方法集合 | 只能被 `tighten_sandbox` 收紧 |
| 句柄 `handle` | `(owner, handle_no, generation)`、父句柄、资源与**授权时的资源代数**、`rights`、会话代数、`[not_before, not_after]`、沙箱标签 | 同一 `(owner, handle_no)` 每发一次 +1 |

方法只有三种：`read`、`write`、`list`。资源固定拥有 `tenant`、代数与这三项权限
的一个子集；句柄的权限不得超出资源支持的集合。

### 1.2 传递只能缩减

`transfer` 从父句柄派生一个子句柄，必须同时满足：

* 子权限 ⊆ 父链**有效权限**（父链各跳 `rights` 与各沙箱允许集合的交集），否则
  `E_RIGHTS_ESCALATION`；
* 子窗口 ⊆ 父句柄窗口，即 `not_before >= 父.not_before` 且
  `not_after <= 父.not_after`，否则 `E_WINDOW_ESCALATION`；
* 子句柄可以**追加**沙箱标签，不能删掉继承来的标签；
* 父链在传递这一刻必须是结构有效的（代数未过期、会话未重启、资源未重建、未被
  撤销），否则按阻断原因返回对应错误码。

### 1.3 再三收紧的沙箱

句柄可以同时属于多个沙箱。判定时**每个沙箱都必须允许**该操作——不是"任一"，
也不是"最后一个赢"。沙箱的允许集合在判定时从库里**实时读取**，所以一次
`tighten_sandbox` 会立即作用于已经发出去的句柄，无需重新签发。

`tighten_sandbox` 只接受严格变小（至少移除一项、不新增任何项），并允许一路收紧
到「什么都不允许」。

### 1.4 失效的四个来源

沿父链的任何一跳出现下列情况，后代即失效：

| 原因 `reason` | 触发 | 阻断点 |
| --- | --- | --- |
| `HANDLE_REVOKED` | `revoke` 该句柄 | 该句柄所在的一跳 |
| `SESSION_GENERATION_MISMATCH` | 进程 `restart_process`，句柄记录的会话代数落后 | 该句柄所在的一跳 |
| `RESOURCE_GENERATION_MISMATCH` | 资源 `rebuild_resource`，句柄记录的资源代数落后 | 该句柄所在的一跳 |
| `HANDLE_SUPERSEDED` | 同一 `(owner, handle_no)` 已存在更新的代数 | 该句柄所在的一跳 |
| `SANDBOX_DENIED` | 该句柄（或其祖先）携带的某个沙箱不允许此方法 | 引入该标签的那一跳 |

**旧代不会因为重新授权而复活。** 撤销句柄 5 的代数 1 之后，再以相同权限在同号
上签发，得到的是代数 2；代数 1 依然 `HANDLE_REVOKED` + `HANDLE_SUPERSEDED`。
会话代数、资源代数同理。

### 1.5 判定的优先级

每次 `check` / `precheck` / `protected_io` 都会**收集全部失败项**，然后排序：

1. 先按 `hop` 升序（`hop=0` 是叶子句柄，`hop=1` 是它的父，依此类推）；
2. 同一跳内按固定的 `reason` 顺序：
   `HANDLE_SUPERSEDED` → `PROCESS_NOT_FOUND` → `PROCESS_DEAD` →
   `SESSION_GENERATION_MISMATCH` → `HANDLE_REVOKED` → `RESOURCE_NOT_FOUND` →
   `RESOURCE_GENERATION_MISMATCH` → `RESOURCE_MISMATCH` → `NOT_YET_VALID` →
   `EXPIRED` → `METHOD_NOT_GRANTED` / `ANCESTOR_MISSING_RIGHT` →
   `RESOURCE_METHOD_UNSUPPORTED` → `TENANT_MISMATCH` → `SANDBOX_DENIED`。

`blocker` 是排序后的第一项；`blocking_ancestor` 是**第一个 `hop >= 1` 的失败项**。
这两者常常不是同一个：叶子因为 `METHOD_NOT_GRANTED` 被拒时，`blocker` 在 `hop=0`，
而 `blocking_ancestor` 会指向真正收紧权限的祖先。

### 1.6 受保护的多资源操作

`protected_io` 在**一个** `BEGIN IMMEDIATE` 事务里完成全部判定与写入。

* `mode = "all_or_nothing"`：所有条目都允许时才写入全部模拟 I/O，并且**只写一条**
  业务收据；任何一条被拒则整笔拒绝，`io_written` 为空，`receipt_written=false`。
* `mode = "best_effort"`：只写允许的条目；若全部允许则同样写一条收据，否则
  `status="partial"` 且不写收据。

收据内容是对 `{op_id, txn_id, process, mode, items[...], io_seqs, created_ms}` 的
规范化 JSON 做 SHA-256，收据本身也落库，`io_seqs` 指向同事务写入的 `io_log.seq`。

### 1.7 预检快照

`precheck` 可以在事务之外签发：它记录 token、叶子句柄的**确切 handle_id 与代数**、
整条父链上每一跳的 `handle_id / generation / rights / resource_generation /
session_generation / window / sandboxes`，以及 `expires_at`。

把 token 放进 `protected_io` 时，服务**不信任快照内容**，而是：

1. 检查 token 存在、未使用、未过期、且签发时的 `(process, handle, generation,
   method, resource)` 与本次条目一致；
2. 重新读取当前世界，把快照里的每一个 `handle_id` 与实际父链逐项比对——父链被
   替换、被截断、多出一跳都会得到 `CHAIN_CHANGED`；
3. 沿当前父链重新判定每一条授权、资源代数、会话代数、时间窗、沙箱集合；
4. 生成 `recheck` 报告，逐跳记录上述五项是否仍然成立。

任何一步失败都**不写部分 I/O**：整笔事务回滚，`io_written` 为空。

### 1.8 重复消费 ID

`op_id` 是消费 ID。第一次执行（无论提交还是拒绝）都会把结果写进 `transactions`
并保存在 `result_json`。之后用同一个 `op_id` 再来：

* 直接返回**第一次已提交的结果**，`replayed=true`，`txn_id`、收据、
  `receipt_sha256` 全部一致；
* **不再重算历史权限**——即使这期间句柄被撤销、资源被重建、时钟前进，返回的
  仍然是当初的答案；
* 如果这次的请求内容与当初不同，额外给出 `replay_mismatch=true` 和两个
  `request_digest`，但**依然返回旧结果**。

回放检查与结果写入在同一个 `BEGIN IMMEDIATE` 事务内完成，因此并发重复提交只会
有一次真正执行，其余全部走回放。回放也跨进程有效：杀掉进程后重开同一个库文件，
仍然返回第一次的结果。

---

## 2. 输入

`cases.json` 的顶层结构：

```json
{
  "format": "sandbox-cases/1",
  "description": "...",
  "cases": [
    { "case_id": "01_basic_allow_deny",
      "steps": [ { "op": "set_clock", "now_ms": 1000, "label": "01#00" }, ... ] }
  ]
}
```

* `format` 必须为 `sandbox-cases/1`（缺省时视为该值）。
* `case_id` 必须唯一、非空。
* 每个用例在**独立的数据库文件**上执行，用例之间完全隔离。
* `label` 是可选字符串，原样回显到输出里，`cases.json` 用它给每一步一个稳定
  的、可被测试和 README 引用的名字。

### 2.1 操作

| `op` | 必填字段 | 可选字段 | 说明 |
| --- | --- | --- | --- |
| `set_clock` | `now_ms` | | 设置模拟时钟；不允许倒退 |
| `create_process` | `process` | | 创建进程，会话代数 = 1 |
| `restart_process` | `process` | | 会话代数 +1，旧代句柄全部失效 |
| `create_resource` | `resource`、`tenant` | `rights`（默认全三种） | 新建资源，代数 = 1 |
| `rebuild_resource` | `resource` | | 资源代数 +1 |
| `create_sandbox` | `sandbox`、`rights` | | 新建沙箱的允许集合 |
| `tighten_sandbox` | `sandbox`、`rights` | | 只能严格变小，可为 `[]` |
| `grant` | `process`、`handle`、`resource`、`rights` | `generation`、`not_before`、`not_after`、`sandboxes` | 签发根句柄 |
| `transfer` | `parent{process,handle[,generation]}`、`to_process`、`handle` | `rights`（缺省继承父链有效权限）、`generation`、`not_before`、`not_after`、`sandboxes` | 派生（多代）子句柄 |
| `revoke` | `process`、`handle` | `generation`（缺省取该号最新代） | 撤销，幂等 |
| `check` | `process`、`handle`、`method` | `generation`、`resource`、`tenant` | 单次判定 |
| `precheck` | `process`、`handle`、`method` | `generation`、`resource`、`ttl_ms`（默认 60000） | 签发预检快照 |
| `protected_io` | `op_id`、`process`、`items[]` | `mode`（默认 `all_or_nothing`）、`fault` | 受保护的多资源操作 |
| `handle_info` | `process`、`handle` | `generation` | 读句柄与整条父链 |
| `list_slot` | `process`、`handle` | | 读同一句柄号的所有代数 |
| `io_audit` | | `op_id` | 读模拟 I/O、事务与收据审计 |
| `decision_log` | | `limit` | 读全部判定审计 |
| `snapshot_stats` | | | 在**一个快照事务**里读取各表计数（并发读者用） |

`protected_io` 的 `items[]` 每项：

```json
{"handle": 1, "method": "write", "resource": "r1", "payload": "a",
 "generation": 1, "precheck": "P0002", "tenant": "t1"}
```

`generation`、`precheck`、`tenant`、`payload` 均可省略。给了 `precheck` 时，
`generation` 以快照为准——授权的是哪一代，用的就是哪一代。

`fault` 只接受 `"io_uncommitted"` 与 `"committed_unacked"`，并且必须显式开启
（`--allow-faults` 或环境变量 `SANDBOX_ALLOW_FAULTS=1`），否则报
`E_FAULT_NOT_ALLOWED`。两种故障都用 `os._exit` 直接终止进程，绕过 `finally`、
`atexit` 与 `__del__`。

---

## 3. 输出

```json
{
  "format": "sandbox-service/1",
  "input": "cases.json",
  "cases": [
    {
      "case_id": "09_protected_io_modes",
      "db": ".../09_protected_io_modes.sqlite3",
      "steps": [
        {"step_index": 6, "label": "09#06", "op": "grant", "ok": true,
         "result": {"status": "ok", "code": "OK", ...}},
        {"step_index": 8, "label": "09#08", "op": "protected_io", "ok": true,
         "result": {"status": "ok", "txn_id": "T0001",
                    "io_written": [{"io_id": 1, "seq": 1, "handle": 1,
                                    "generation": 1, ...}],
                    "receipt": {"receipt_id": 1, "receipt_seq": 1,
                                "receipt_sha256": "169f41e7…",
                                "body": {...}},
                    "receipt_written": true, "replayed": false}}
      ]
    }
  ]
}
```

* 请求级失败：`{"ok": false, "error": {"code": "E_...", "error": "...", "detail": ...}}`。
* 能力拒绝不是请求错误：`ok` 仍为 `true`，`result.decision == "deny"`，
  `result.code` 为拒绝码，`result.blocker` / `result.blocking_ancestor` 给出阻断点。
* 输出是确定性的：不含墙钟时间、不含随机数，只依赖输入与执行顺序。除每个用例的
  `db` 路径外，重复运行得到完全相同的 JSON（`tests/test_cli.py` 断言了这一点）。

### 3.1 判定对象

`check` / `precheck` / `protected_io` 的每一项都会给出：

```json
{
  "decision": "deny",
  "blocker": {"reason": "HANDLE_REVOKED", "code": "E_HANDLE_REVOKED",
              "hop": 1, "owner": "p2", "handle": 2, "generation": 1,
              "handle_id": 2, "revoked_ms": 1000},
  "blocking_ancestor": {"reason": "HANDLE_REVOKED", "hop": 1, "owner": "p2",
                        "handle": 2, "generation": 1},
  "failures": [ ... 全部失败项，已排序 ... ],
  "chain": [ ... 从叶子到根的每一跳，含 handle_id / generation / rights ... ],
  "effective_rights": ["read"]
}
```

`generation` 永远是**被检查对象的真实代数**。句柄根本不存在时
`generation` 为 `null`，请求的代数放在 `requested_generation` 里——因为不存在
的代数不能冒充阻断点。

---

## 4. 错误码

### 4.1 请求级错误（`ok=false`）

| 代码 | 含义 |
| --- | --- |
| `E_INVALID_REQUEST` | 字段缺失、类型错误、未知方法名、空 rights、`not_after < not_before`、空 items、未知 mode |
| `E_UNKNOWN_OP` | 未知 `op` |
| `E_ALREADY_EXISTS` | 进程 / 资源 / 沙箱重名 |
| `E_GENERATION_CONFLICT` | 显式指定的句柄代数不大于该号现有最大代数 |
| `E_TIME_REGRESSION` | `set_clock` 倒退 |
| `E_PROCESS_NOT_FOUND` / `E_PROCESS_DEAD` | 进程不存在 / 不存活 |
| `E_RESOURCE_NOT_FOUND` / `E_SANDBOX_NOT_FOUND` | 资源 / 沙箱不存在 |
| `E_HANDLE_NOT_FOUND` | 要撤销 / 派生 / 查询的句柄不存在 |
| `E_RIGHTS_ESCALATION` | 派生时要求父链没有的权限 |
| `E_WINDOW_ESCALATION` | 派生时窗口超出父句柄窗口 |
| `E_SANDBOX_NOT_NARROWING` | `tighten_sandbox` 没有严格变小 |
| `E_NO_RIGHTS` | 权限集合为空 |
| `E_FAULT_NOT_ALLOWED` | 未开启故障注入却给了 `fault` |
| `E_INTERNAL` | 不应发生的内部错误（含父链成环） |

### 4.2 能力拒绝码（`ok=true`，`decision=deny`）

`code` 与 `blocker.reason` 一一对应，`reason` 是稳定的机器可读值，`code` 是
对外错误码：

| `reason` | `code` |
| --- | --- |
| `HANDLE_NOT_FOUND` | `E_HANDLE_NOT_FOUND` |
| `HANDLE_SUPERSEDED` | `E_HANDLE_SUPERSEDED` |
| `HANDLE_REVOKED` | `E_HANDLE_REVOKED` |
| `SESSION_GENERATION_MISMATCH` | `E_SESSION_STALE` |
| `RESOURCE_GENERATION_MISMATCH` | `E_RESOURCE_GENERATION_MISMATCH` |
| `RESOURCE_MISMATCH` | `E_RESOURCE_MISMATCH` |
| `METHOD_NOT_GRANTED` | `E_METHOD_NOT_GRANTED` |
| `ANCESTOR_MISSING_RIGHT` | `E_ANCESTOR_MISSING_RIGHT` |
| `RESOURCE_METHOD_UNSUPPORTED` | `E_RESOURCE_METHOD_UNSUPPORTED` |
| `NOT_YET_VALID` | `E_NOT_YET_VALID` |
| `EXPIRED` | `E_EXPIRED` |
| `TENANT_MISMATCH` | `E_TENANT_MISMATCH` |
| `SANDBOX_DENIED` | `E_SANDBOX_DENIED` |
| `PARENT_MISSING` | `E_PARENT_MISSING` |
| `PROCESS_NOT_FOUND` | `E_PROCESS_NOT_FOUND` |
| `PROCESS_DEAD` | `E_PROCESS_DEAD` |
| `RESOURCE_NOT_FOUND` | `E_RESOURCE_NOT_FOUND` |

### 4.3 预检专用码

| `reason` | `code` | 含义 |
| --- | --- | --- |
| `PRECHECK_NOT_FOUND` | `E_PRECHECK_NOT_FOUND` | token 不存在 |
| `PRECHECK_USED` | `E_PRECHECK_USED` | token 已被消费 |
| `PRECHECK_EXPIRED` | `E_PRECHECK_EXPIRED` | 已过 `expires_at` |
| `PRECHECK_MODE_MISMATCH` | `E_PRECHECK_MODE_MISMATCH` | 签发时的 process/handle/generation/method/resource 与本次不符 |
| `CHAIN_CHANGED` | `E_PRECHECK_STALE` | 父链上的 `handle_id` 序列与快照不一致 |

---

## 5. 实测结果

以下数字来自本机（Windows 11、Python 3.12.8、SQLite 3.45.3）实际运行。

### 5.1 自动化测试

```
$ python -m unittest discover -s tests -v
...
Ran 88 tests in 13.4s

OK
```

88 个用例全部通过，分布：

| 文件 | 数量 | 覆盖 |
| --- | --- | --- |
| `tests/test_engine.py` | 50 | 判定优先级、衰减、沙箱交集、回收复用、预检、I/O 模式、幂等、持久化、审计 |
| `tests/test_crosscheck.py` | 8 | 与独立参考模型逐项比对（含 80 步随机游走 + 300 次穷举复核） |
| `tests/test_crash.py` | 6 | 两处硬终止、崩溃后重试、写读两进程并发 |
| `tests/test_cli.py` | 24 | CLI 全量重放、确定性、输入校验、每个场景的具体断言 |
| 合计 | 88 | |

### 5.2 两处故障终止

| 场景 | 子进程退出码 | 库内可见 |
| --- | --- | --- |
| `io_uncommitted`（写入后未提交即终止） | 70 | `io_count=0`、`receipt_count=0`、`txn_count=0` |
| `committed_unacked`（提交后未应答即终止） | 71 | `io_count=2`、`receipt_count=1`、事务状态 `committed` |

崩溃后重试：

* 在 `io_uncommitted` 之后重试同一 `op_id` → 这不是回放而是首次执行
  （`replayed=false`），得到 `T0001` 并正好提交一次：`io_count=1`、`receipt_count=1`。
* 在 `committed_unacked` 之后先 `revoke` 再重试同一 `op_id` → `replayed=true`、
  `replay_of_state="committed"`、收据哈希与崩溃前一致，I/O 行数不增加。

### 5.3 并发读者

一个写进程连续提交 150 笔两资源事务（300 行 I/O、150 条收据），另一个读进程在
整个写过程期间循环调用 `snapshot_stats`（每次都跑在一个读快照事务里）。读进程
采样到的每个快照都满足：

* `orphan_receipts == 0`（不存在没有 I/O 的收据）
* `receipts == committed_transactions`
* `io_rows == committed_transactions × 2`
* `transactions == committed + denied`（看不到中间态）

即读者**从未看到半笔提交**。写进程结束后统计为 `receipt_count=150`、`io_count=300`。

### 5.4 `cases.json` 的关键判定

| 步骤 | 场景 | 结论 |
| --- | --- | --- |
| `01#06` | 只有 read/write 时请求 list | `METHOD_NOT_GRANTED`，`hop=0`，`generation=1` |
| `02#11` | 孙代只有 read，试图派生 read+write | `E_RIGHTS_ESCALATION` |
| `02#12` | 派生时把 `not_after` 放大 | `E_WINDOW_ESCALATION` |
| `02#16` | 收窄窗口后时钟越过它 | `EXPIRED`，`hop=0` |
| `03#08` | 同时属于 `sb_ro` 与 `sb_all`，请求 write | `SANDBOX_DENIED`，`sandbox=sb_ro`，允许集合 `["read","list"]` |
| `03#11` | `sb_all` 收紧掉 list 后请求 list | `SANDBOX_DENIED`，`sandbox=sb_all` |
| `04#08` | 祖先进程重启后访问孙代 | `SESSION_GENERATION_MISMATCH`，`hop=1`，`generation=1`，`blocking_ancestor=(p1,1,1)` |
| `05#06` | 资源重建后旧句柄 | `RESOURCE_GENERATION_MISMATCH`，`blocker.generation=1`、`resource_generation=2` |
| `06#06` | 同号两代，显式取旧代 | `HANDLE_SUPERSEDED`，`generation=1`，`newest_generation=2` |
| `06#08` | 显式要求低于现存的代数 | `E_GENERATION_CONFLICT` |
| `07#10` | 撤销中间祖先 p2 的句柄 2 | `HANDLE_REVOKED`，`hop=1`，`generation=1`，`revoked_ms=1000` |
| `07#11` | 同上，读整条链 | 链长 3，`(p3,1) (p2,1) (p1,1)`，`structurally_valid=false` |
| `07#14` | 同根的另一分支 | `allow`（不受影响） |
| `08#08` | 撤销后发同权同号句柄，再取旧代 | `HANDLE_SUPERSEDED`，`generation=1`，旧代未复活 |
| `09#08` | 三资源 all_or_nothing 全部允许 | `status=ok`，`io=[1,2,3]`，`receipt_sha256=169f41e7c79e…`，`T0001` |
| `09#09` | 同一 `op_id` 再来一次 | `replayed=true`，`T0001`，收据哈希不变 |
| `09#11` | 三资源中一项被撤权 | `status=denied`，`io_written=[]`，`blockers=1`（`HANDLE_REVOKED`，item 1） |
| `09#12` | 同样的输入改用 best_effort | `status=partial`，只写 handle 1，无收据 |
| `10#09` | 预检后重建资源再使用 | `RESOURCE_GENERATION_MISMATCH`，不写 I/O |
| `10#12` | 重新授权、重新预检后使用 | `status=ok`，`receipt_sha256=e8cce4f505cb…` |
| `10#13` | 重复使用同一 token | `PRECHECK_USED` |
| `10#16` | 超过 `expires_at` 使用 | `PRECHECK_EXPIRED` |
| `10#17` | 使用不存在的 token | `PRECHECK_NOT_FOUND` |
| `10#19` | 用 read 的 token 做 write | `PRECHECK_MODE_MISMATCH` |
| `12#14` | 同一 `op_id`、条目顺序相反、资源已重建 | `replayed=true`，`replay_mismatch=true`，仍返回 `T0001` 的旧结果 |
| `13#07` | 沙箱收紧为空后再判定 | `SANDBOX_DENIED`，`sandbox=sb`，允许集合 `[]` |

完整结果见 `python -m solution --input cases.json --output result.json` 生成的
`result.json`（约 240 KB）。

---

## 6. 实现说明

```
solution/
  __init__.py        版本与输出格式常量
  __main__.py        CLI：读 cases.json，逐用例建库执行，写 result.json
  engine.py          事务边界、各 op 的实现、预检复查、受保护 I/O 与故障点
  capability.py      纯函数的能力判定：父链遍历、失败收集与排序、复查报告
  db.py              SQLite  schema、连接与事务辅助
  errors.py          错误码表与 reason→code 映射
  util.py            规范化 JSON、摘要、位掩码与字段校验
tests/
  reference_model.py 独立参考模型（不导入 solution 的任何代码）
  support.py         Engine 与参考模型的双跑镜像
  test_engine.py     语义与持久化
  test_crosscheck.py 与参考模型逐项比对
  test_crash.py      独立进程故障与并发
  test_cli.py        CLI 全量重放与具体断言
tools/make_cases.py 生成 cases.json（确定性，可重新生成后 diff）
```

### 6.1 一致性

* 每次判定都把**全部**相关状态读进一个不可变的 `World`，判定是它的纯函数，
  相同的世界必然给出相同的结论。
* 写事务一律 `BEGIN IMMEDIATE`，锁的获取是确定的；读者用延迟读事务，在 WAL 上
  固定在一个提交点，跨多条查询也不会看到半笔提交。
* 父链的失效**不级联写库**：`revoke` 只标记被撤销的那一行，后代由父链遍历判定。
  这样报告里永远能给出"是哪一代的哪个祖先阻断的"，而不是丢失在级联更新的过程里。

### 6.2 独立能力模型

`tests/reference_model.py` 是一个约 330 行的独立实现：纯 Python 字典与列表，
不导入 `solution`，按 README 的规则重新写了一遍遍历与优先级。测试把每一步同时喂
给两边，要求**允许/拒绝、blocker 的 reason/hop/generation、blocking_ancestor 的
owner/hop/generation、完整的 failures 列表**全部一致。除了 7 个手写场景，还有
一次固定种子（`20261120`）的 80 步随机游走，最后对 4 个进程 × 5 个句柄号 ×
5 种代数 × 3 种方法 = 300 种组合做穷举复核。

---

## 7. 复现

```bash
# 1. 全量重放
python -m solution --input cases.json --output result.json

# 2. 自动化测试
python -m unittest discover -s tests -v

# 3. 重新生成用例（应无差异）
python tools/make_cases.py && git diff --exit-code cases.json
```

需要观察故障终止时，显式开启并自行处理退出码：

```bash
python -m solution --input cases.json --output /tmp/r.json --allow-faults
```

`cases.json` 本身不含 `fault` 步骤（正常重放必须是有限步且可重放），故障路径由
`tests/test_crash.py` 用 `subprocess` 单独驱动。
