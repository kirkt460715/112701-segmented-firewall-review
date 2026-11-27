# 生态专网分区防火墙的规则变更审查

对象、网关和策略均用合成标识。资料只包含声明的许可、拒绝样本和审批回执。 资料均为本地合成记录。

以 Python 3.11.2 运行，无第三方依赖。`records/` 中的 `entitlements`、`policy`、`receipts` 对应独立来源。每份材料是 JSON 对象数组，`id` 在同一来源内唯一。报告和观察的时间以各原始记录给出的字段为准。

```sh
python3 -m unittest -v
python3 records_view.py
```

资料入口列出来源、记录标识及条数。通过 `--source` 指定来源，`--offset` 和 `--limit` 限定读取的位置与数量。`--records` 可指定同样结构的其他资料目录。

## 审查服务

`review_service.py` 在只读资料之上做本地审查，本身不下发任何变更（下发归独立设备团队）。审查时刻用 `--at` 显式给出，缺省取回执中的最晚时间；输出中无法确认的范围都带 `responsible`，区分安全员（`security-officer`，源材料问题）与设备团队（`device-team`，执行/回执问题）。

```sh
# 核对变更：同名对象跨网关对应、审批时段、最小权限与预期许可/拒绝用例
python3 -I review_service.py review --at 60

# 回执核销：逐网关签收/生效状态，旧版本回执不抵消新版本偏差
python3 -I review_service.py receipts

# 回退复核：上次核实基线在当前约束下是否仍可回退
python3 -I review_service.py rollback --gateway gw-2 --at 130

# 值班台分项接办：审批 / 预期策略结果 / 当前真实生效区域
python3 -I review_service.py lookup --kind approval --owner county-b --at 60
python3 -I review_service.py lookup --kind expected --gateway gw-1
python3 -I review_service.py lookup --kind effective
```

审查规则要点：

- 同名对象按网关分别解析成员；成员不一致时标记 `divergent`，对象更名/重定义对审批范围的影响随变更一起输出。
- 临时许可看批准时段（`expires`/`effective` 对应 active/pending/expired）；未到生效时刻或材料缺失只产生 `unconfirmed`，不臆断放行或拒绝。
- 共享对象上的 deny 逐成员核对：有吊销审批的为 `authorized`，仍有邻县有效授予的为 `over_reach`，并在 `narrow_to` 中给出可执行的最小范围，避免连同另一县有效权限一起收回。
- 预期用例与候选策略逐条比对（`consistent`/`conflict`/`not_affected`/`unconfirmed`），规则位置非首位时记录前置规则遮挡的不确定性。
- 一个网关签收而另一个未签时，未确认范围留给设备团队；旧版本回执单列在 `stale_receipts`，不能消除新版本配置偏差。
- `last_verified` 保留各网关最近一次核实配置及适用条件；回退选项必须通过当前约束复核，条件已失效时判为 `blocked`。
