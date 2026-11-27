# 生态专网分区防火墙的规则变更审查

对象、网关和策略均用合成标识。资料只包含声明的许可、拒绝样本和审批回执。 资料均为本地合成记录。

以 Python 3.11.2 运行，无第三方依赖。`records/` 中的 `entitlements`、`policy`、`receipts` 对应独立来源。每份材料是 JSON 对象数组，`id` 在同一来源内唯一。报告和观察的时间以各原始记录给出的字段为准。

```sh
python3 -m unittest -v
python3 records_view.py
```

资料入口列出来源、记录标识及条数。通过 `--source` 指定来源，`--offset` 和 `--limit` 限定读取的位置与数量。`--records` 可指定同样结构的其他资料目录。

## 审查服务

`review.py` 只做离线核对，不下发配置。`--at` 指定审查时点（缺省取回执中最晚的观察时间），`--change` 只审查指定变更。

```sh
python3 review.py
python3 review.py --at 50 --change rule-review
```

审查结果的几个部分彼此独立：

- `approvals`：按批准方向、来源区、业务、时段和所有者核对许可；共享对象逐网关对照实际成员，临时例外只在批准窗口内且所有者清楚时有效。
- `policy`：候选规则、规则顺序影响（同位置、遮蔽、冗余）、同名对象跨网关差异及对象更名。
- `expected`：合成预期用例与候选策略逐条核对，区分 `match`、`mismatch`、`unconfirmed` 和 `not_affected`（候选中无适用规则，不推断结果）。
- `receipts` / `actual_effective`：签收与生效分开看；未生效的网关交给设备团队，旧版本回执只说明旧配置被观察到，不清除本次偏差。
- `rollback`：保留上次核实配置，但须按当前审批窗口、撤销状态和对象映射重新通过条件。
- `uncertain`：来源缺失、对象无法对应、所有者不清或回执不足时列出的无法确认范围。

一次变更需要缩小时，`findings` 中的 `shared_object_overreach` 给出必须保留的其他县许可和可缩小的来源区；报告始终带 `review_only: true`，下发由设备团队负责。

