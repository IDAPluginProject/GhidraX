# PyGhidra 代码还原总计划

> 目标：将 Ghidra C++ 反编译器完整移植为纯 Python 实现
> 基准：cpp/ 下 C++ 源码为行为标准，SLEIGH 引擎保留 C++ (pybind11)
> 当前状态：1035 tests, 81 Python 模块已移植，但 60+ 模块缺少单元测试

---

## 现状总览

### 已移植 ✅ (81 个 Python 模块)

| 层 | 模块 | 有测试? |
|---|---|---|
| **core/** | address, space, pcoderaw, opcodes, opbehavior, error, marshal, float_format, compression, capability, filemanage, libdecomp, globalcontext, expression, int128, translate, types(datatype) | float_format✓ compression✓ filemanage✓ libdecomp✓ opbehavior✓ 其余❌ |
| **ir/** | varnode, op, typeop, variable, cover | 仅通过 test_ir_classes 间接覆盖 |
| **transform/** | action, coreaction, coreaction2, ruleaction(+12 batch), condexe, deadcode, nzmask, universal | condexe✓ transform✓ 其余仅通过 mini_pipeline 间接覆盖 |
| **analysis/** | funcdata, flow, heritage, merge, dynamic, callgraph, graph, constseq, prefersplit, rangeutil, subflow, double | callgraph✓ 其余❌ |
| **block/** | block, blockaction, collapse | ❌ |
| **output/** | prettyprint, printlanguage, printc | ❌ |
| **database/** | database, comment, cpool, stringmanage | ❌ |
| **types/** | datatype, cast | types✓ 其余❌ |
| **fspec/** | fspec, paramactive, modelrules, paramid | modelrules✓ paramid✓ 其余❌ |
| **arch/** | architecture, loadimage, loadimage_xml, options, userop, override, inject | loadimage_xml✓ 其余❌ |
| **emulate/** | emulate, memstate, emulateutil | emulateutil✓ 其余❌ |
| **sleigh/** | lifter, slaformat, sleigh, sleighbase, bridge_validator, decompiler_python | bridge✓ decompiler_python✓ lifter✓ |
| **console/** | interface, ifaceterm, protocol, consolemain, ghidra_arch, ghidra_process, subsystems | interface✓ ifaceterm✓ protocol✓ 其余❌ |

### 未移植 ❌ (C++ 模块)

| 分类 | C++ 文件 | 行数 | 优先级 |
|---|---|---|---|
| **架构初始化** | sleigh_arch.cc | 555 | 🔴 关键 |
| **架构变体** | raw_arch.cc | 101 | 🟡 中等 |
| **架构变体** | xml_arch.cc | 132 | 🟡 中等 |
| **P-code注入** | inject_sleigh.cc | 457 | 🔴 关键 |
| **P-code编译** | pcodecompile.cc | 693 | 🟡 中等 |
| **Java输出** | printjava.cc | 325 | 🟢 低 |
| **反编译器CLI** | ifacedecomp.cc | 3192 | 🟡 中等 |
| **代码/数据分析** | codedata.cc | 684 | 🟡 中等 |
| **签名分析** | signature.cc | 1013 | 🟢 低 |
| **签名CLI** | analyzesigs.cc | 202 | 🟢 低 |
| **测试框架** | testfunction.cc + test.cc | 511 | 🟡 中等 |
| **Ghidra后端** | database_ghidra, inject_ghidra, ghidra_translate 等 10个 | ~1100 | 🟡 中等 |

### 不需要移植 ⛔ (SLEIGH 编译器，保留 C++)

slgh_compile.cc (3706), slghparse.cc (3320), slghscan.cc (3171), grammar.cc (2852),
pcodeparse.cc (2905), slghsymbol.cc (2104), slghpatexpress.cc (1383), unify.cc (1353),
semantics.cc (845), slghpattern.cc (842), rulecompile.cc (883), context.cc (210),
sleighexample.cc (343), bfd_arch.cc (144), loadimage_bfd.cc (258)

> 原因：SLEIGH 引擎是唯一允许保留 C++ 的模块 (sleigh_native.pyd)
> BFD 相关模块是 Linux 专用，Windows 上不需要

---

## 六阶段还原计划

---

### Phase 0: 测试债务清零 (Test Debt)

**目的**：为所有已移植但缺少单元测试的模块补全测试，确保现有代码的正确性基线。

#### Step 0.1 — Core 层基础测试

| 任务 | 对应 C++ | Python 模块 | 测试文件 | 预计测试数 |
|---|---|---|---|---|
| Override 系统 | override.cc (371行) | arch/override.py | test_override.py | 15-20 |
| Options 系统 | options.cc (944行) | arch/options.py | test_options.py | 20-25 |
| UserOp 注册表 | userop.cc (577行) | arch/userop.py | test_userop.py | 15-20 |
| Capability 注册 | capability.cc (43行) | core/capability.py | test_capability.py | 5-8 |
| GlobalContext 上下文 | globalcontext.cc (547行) | core/globalcontext.py | test_globalcontext.py | 10-15 |
| Expression 匹配 | expression.cc (516行) | core/expression.py | test_expression.py | 15-20 |
| Inject 注入框架 | pcodeinject.cc (324行) | arch/inject.py | test_inject.py | 10-15 |

**测试重点**：
- override: 所有 insert/query/apply 方法 + typeToString/stringToType 转换 + encode/decode 往返
- options: ArchOption.onOrOff + OptionDatabase.set + 各具体选项的 apply 行为
- userop: UserOpManage 注册/查找 + 各子类构造 + getDisplay/setDisplay
- capability: 注册/初始化/清除生命周期
- globalcontext: ContextBitRange 位操作 + ContextInternal 设置/读取 + 默认值
- expression: PcodeOpNode 排序 + TraverseNode 路径判断 + BooleanMatch 全分支
- inject: InjectPayload 类型常量 + 基本 get/set

#### Step 0.2 — IR/Analysis 层测试

| 任务 | 对应 C++ | Python 模块 | 测试文件 | 预计测试数 |
|---|---|---|---|---|
| Block 图结构 | block.cc (3243行) | block/block.py | test_block.py | 20-25 |
| Heritage SSA | heritage.cc (2673行) | analysis/heritage.py | test_heritage.py | 15-20 |
| Funcdata 核心 | funcdata*.cc (5392行) | analysis/funcdata.py | test_funcdata.py | 20-25 |
| Merge 变量合并 | merge.cc (1552行) | analysis/merge.py | test_merge.py | 10-15 |
| Cover 活跃范围 | cover.cc (571行) | ir/cover.py | test_cover.py | 10-15 |
| Dynamic 动态哈希 | dynamic.cc (694行) | analysis/dynamic.py | test_dynamic.py | 10-15 |

**测试重点**：
- block: 10 种 FlowBlock 子类的 构造/边操作/编码解码/nextInFlow/getFrontLeaf
- heritage: renameRecurse + phi 节点插入 + 单函数 SSA 构造端到端
- funcdata: 基本块/Varnode/PcodeOp 操作 + opSetInput/opSetOutput + 状态管理
- merge: Merge 策略 + 变量冲突检测
- cover: CoverBlock 添加/包含/合并/打印
- dynamic: DynamicHash 计算 + 地址恢复

#### Step 0.3 — Database/Symbol/FSpec 层测试

| 任务 | 对应 C++ | Python 模块 | 测试文件 | 预计测试数 |
|---|---|---|---|---|
| Database 作用域 | database.cc (3077行) | database/database.py | test_database.py | 15-20 |
| VarMap 局部变量 | varmap.cc (1487行) | analysis/varmap.py | test_varmap.py | 10-15 |
| Resolve 联合体 | unionresolve.cc (1063行) | analysis/resolve.py | test_resolve.py | 10-15 |
| FSpec 函数签名 | fspec.cc (5397行) | fspec/fspec.py | test_fspec.py | 20-25 |
| Comment 注释 | comment.cc (356行) | database/comment.py | test_comment.py | 8-10 |
| CPool 常量池 | cpool.cc (220行) | database/cpool.py | test_cpool.py | 8-10 |
| StringManage 字符串 | stringmanage.cc (433行) | database/stringmanage.py | test_stringmanage.py | 8-10 |

#### Step 0.4 — Transform 层测试

| 任务 | 对应 C++ | Python 模块 | 测试文件 | 预计测试数 |
|---|---|---|---|---|
| RangeUtil 范围运算 | rangeutil.cc (2449行) | analysis/rangeutil.py | test_rangeutil.py | 15-20 |
| SubFlow 子变量 | subflow.cc (3833行) | analysis/subflow.py | test_subflow.py | 10-15 |
| Double 分裂变量 | double.cc (3341行) | analysis/double.py | test_double.py | 10-15 |
| ConstSeq 常量序列 | constseq.cc (941行) | analysis/constseq.py | test_constseq.py | 10-15 |
| PreferSplit 分裂管理 | prefersplit.cc (559行) | analysis/prefersplit.py | test_prefersplit.py | 8-10 |

#### Step 0.5 — Output 层测试

| 任务 | 对应 C++ | Python 模块 | 测试文件 | 预计测试数 |
|---|---|---|---|---|
| PrintLanguage RPN | printlanguage.cc (744行) | output/printlanguage.py | test_printlanguage.py | 15-20 |
| PrettyPrint 排版 | prettyprint.cc (1085行) | output/prettyprint.py | test_prettyprint.py | 10-15 |
| PrintC C输出 | printc.cc (3137行) | output/printc.py | test_printc.py | 25-30 |
| Cast 类型转换 | cast.cc (503行) | types/cast.py | test_cast.py | 10-15 |

**Phase 0 总计**: ~35 个测试文件, ~400-500 个测试用例
**完成标志**: `pytest tests/ --timeout=120` 全部通过，覆盖率显著提升

---

### Phase 1: 架构自举 (Architecture Bootstrap)

**目的**：让 Python 反编译器能独立加载 .sla 文件并完成架构初始化，不依赖 Ghidra GUI。

**前置条件**: Phase 0 完成

#### Step 1.1 — SleighArchitecture (🔴 关键路径)

| 项目 | 说明 |
|---|---|
| **C++ 源** | sleigh_arch.cc/hh (555+143 = 698行) |
| **Python 目标** | arch/sleigh_arch.py |
| **核心类** | SleighArchitectureCapability, SleighArchitecture |
| **功能** | 加载 .sla/.pspec/.cspec 文件，初始化地址空间/寄存器/编译规范 |
| **依赖** | architecture.py, sleigh_native.pyd, inject.py, options.py |
| **测试** | test_sleigh_arch.py: .sla 加载 + 空间初始化 + 寄存器查找 + 编译规范解析 |
| **预计测试数** | 15-20 |

#### Step 1.2 — InjectPayloadSleigh (🔴 关键路径)

| 项目 | 说明 |
|---|---|
| **C++ 源** | inject_sleigh.cc/hh (457+123 = 580行) |
| **Python 目标** | arch/inject_sleigh.py |
| **核心类** | InjectPayloadSleigh, InjectContextSleigh, PcodeInjectLibrarySleigh |
| **功能** | 通过 SLEIGH 引擎执行 p-code 注入片段 (call fixups, CALLOTHER fixups) |
| **依赖** | inject.py, sleigh_native.pyd, architecture.py |
| **测试** | test_inject_sleigh.py: 注入上下文构建 + p-code 片段执行 + fixup 注册/查找 |
| **预计测试数** | 10-15 |

#### Step 1.3 — PcodeCompile

| 项目 | 说明 |
|---|---|
| **C++ 源** | pcodecompile.cc/hh (693+101 = 794行) |
| **Python 目标** | arch/pcodecompile.py |
| **核心类** | PcodeCompile, PcodeSnippet |
| **功能** | 从文本片段编译 p-code (用于 inject_sleigh) |
| **依赖** | inject.py, sleigh_native.pyd |
| **测试** | test_pcodecompile.py: 片段编译 + 语法错误处理 |
| **预计测试数** | 10-15 |

#### Step 1.4 — RawBinaryArchitecture + XmlArchitecture

| 项目 | 说明 |
|---|---|
| **C++ 源** | raw_arch.cc (101行) + xml_arch.cc (132行) |
| **Python 目标** | arch/raw_arch.py, arch/xml_arch.py |
| **功能** | 原始二进制 / XML 格式架构加载 |
| **测试** | test_raw_arch.py, test_xml_arch.py |
| **预计测试数** | 8-10 each |

#### Step 1.5 — 端到端独立反编译测试

| 项目 | 说明 |
|---|---|
| **测试** | test_standalone_decompile.py |
| **内容** | 加载真实 x86 .sla → 读取二进制 → 完整反编译 → 输出 C 代码 |
| **验证** | 不依赖任何 Ghidra 组件，纯 Python + sleigh_native.pyd 独立运行 |
| **预计测试数** | 5-10 |

**Phase 1 总计**: ~5 个新模块, ~55-75 个测试
**完成标志**: `python -m ghidra.decompile binary.bin --arch x86:LE:32` 能独立输出 C 代码

---

### Phase 2: 反编译器 CLI (Decompiler CLI)

**目的**：移植交互式命令行界面，支持调试和逐步分析。

**前置条件**: Phase 1 完成

#### Step 2.1 — IfaceDecompData + IfaceDecompCapability

| 项目 | 说明 |
|---|---|
| **C++ 源** | ifacedecomp.cc/hh 数据结构部分 (~500行) |
| **Python 目标** | console/ifacedecomp.py (Part 1) |
| **核心类** | IfaceDecompData, IfaceDecompCapability |
| **功能** | 反编译器状态管理 (Architecture + Funcdata + 当前函数) |
| **测试** | test_ifacedecomp.py (Part 1): 状态初始化/切换/清理 |
| **预计测试数** | 10-15 |

#### Step 2.2 — 核心反编译命令 (~40 个命令)

| 项目 | 说明 |
|---|---|
| **C++ 源** | ifacedecomp.cc 命令部分 (~2700行) |
| **Python 目标** | console/ifacedecomp.py (Part 2+3) |
| **分批** | Batch A: load/save/decompile/print (10 命令) |
| | Batch B: function/symbol/type 查询 (15 命令) |
| | Batch C: action/rule/debug 控制 (15 命令) |
| **测试** | test_ifacedecomp.py (Part 2+3): 每个命令的执行验证 |
| **预计测试数** | 30-40 |

**Phase 2 总计**: ~1 个大模块(分3批), ~40-55 个测试
**完成标志**: `python -m ghidra.console.ifaceterm` 可交互式加载/反编译/查看函数

---

### Phase 3: 功能补全 (Feature Completion)

**目的**：补全剩余的分析和输出功能。

**前置条件**: Phase 1 完成 (Phase 2 可并行)

#### Step 3.1 — PrintJava

| 项目 | 说明 |
|---|---|
| **C++ 源** | printjava.cc/hh (325+72 = 397行) |
| **Python 目标** | output/printjava.py |
| **核心类** | PrintJava (继承 PrintC) |
| **功能** | Java 语言输出 (类型名映射/new/instanceof/数组语法) |
| **测试** | test_printjava.py: 类型输出 + 运算符差异 + 数组语法 |
| **预计测试数** | 15-20 |

#### Step 3.2 — CodeDataAnalysis

| 项目 | 说明 |
|---|---|
| **C++ 源** | codedata.cc/hh (684+178 = 862行) |
| **Python 目标** | analysis/codedata.py |
| **核心类** | CodeDataAnalysis, CodeUnit |
| **功能** | 分析二进制中代码与数据的边界 |
| **测试** | test_codedata.py |
| **预计测试数** | 10-15 |

#### Step 3.3 — Signature Analysis

| 项目 | 说明 |
|---|---|
| **C++ 源** | signature.cc/hh (1013+328 = 1341行) |
| **Python 目标** | analysis/signature.py |
| **功能** | 函数签名特征生成与匹配 |
| **测试** | test_signature.py |
| **预计测试数** | 10-15 |

#### Step 3.4 — TestFunction 框架

| 项目 | 说明 |
|---|---|
| **C++ 源** | testfunction.cc/hh (351+95 = 446行) + test.cc/hh (160+101 = 261行) |
| **Python 目标** | testing/testfunction.py |
| **功能** | 数据驱动的单函数测试框架 |
| **测试** | test_testfunction.py |
| **预计测试数** | 8-10 |

**Phase 3 总计**: ~4 个模块, ~45-60 个测试

---

### Phase 4: Ghidra 协议完善 (Protocol Completion)

**目的**：让 Python 反编译器完全替代 C++ decompiler 进程，对接 Ghidra GUI。

**前置条件**: Phase 1 完成

#### Step 4.1 — Ghidra 后端代理完善

| C++ 源 | Python 目标 | 功能 |
|---|---|---|
| database_ghidra.cc (341行) | console/subsystems.py 扩展 | ScopeGhidra 完整 XML 解码 |
| inject_ghidra.cc (203行) | console/subsystems.py 扩展 | PcodeInjectLibraryGhidra 注入查找 |
| ghidra_translate.cc (158行) | console/subsystems.py 扩展 | GhidraTranslate P-code 提升 |
| comment_ghidra.cc (70行) | console/subsystems.py 扩展 | CommentDatabaseGhidra 注释查询 |
| cpool_ghidra.cc (58行) | console/subsystems.py 扩展 | ConstantPoolGhidra 常量池查询 |
| string_ghidra.cc (42行) | console/subsystems.py 扩展 | GhidraStringManager 字符串查询 |
| typegrp_ghidra.cc (34行) | console/subsystems.py 扩展 | TypeFactoryGhidra 类型工厂 |
| loadimage_ghidra.cc (41行) | console/subsystems.py 扩展 | LoadImageGhidra 字节读取 |
| ghidra_context.cc (36行) | console/subsystems.py 扩展 | ContextGhidra 上下文传递 |
| signature_ghidra.cc (103行) | console/subsystems.py 扩展 | 签名分析后端 |
| **测试** | test_subsystems.py | 每个代理的 XML 解析验证 |
| **预计测试数** | 25-30 |

#### Step 4.2 — Funcdata.encode() 语法树序列化

| 项目 | 说明 |
|---|---|
| **涉及** | analysis/funcdata.py 扩展 |
| **功能** | 将反编译结果序列化为 XML，回传给 Ghidra GUI 显示 |
| **测试** | test_funcdata_encode.py: 序列化 + 反序列化 往返验证 |
| **预计测试数** | 10-15 |

#### Step 4.3 — 端到端 Ghidra 集成测试

| 项目 | 说明 |
|---|---|
| **测试** | test_ghidra_e2e.py |
| **内容** | 模拟 Ghidra 二进制协议 → Python 反编译器处理 → 返回结果 |
| **预计测试数** | 10-15 |

**Phase 4 总计**: ~10 个子模块扩展, ~45-60 个测试
**完成标志**: Python 进程可替代 C++ decompiler 进程，Ghidra GUI 正常显示反编译结果

---

### Phase 5: 全面验证 (Full Validation)

**目的**：确保 Python 输出与 C++ 完全一致。

**前置条件**: Phase 0-4 全部完成

#### Step 5.1 — Bridge Validator 扩展

| 项目 | 说明 |
|---|---|
| **内容** | 扩展 bridge_validator.py 支持 heritage/full 阶段比对 |
| **测试** | test_bridge_advanced.py 扩展: 每个 x86 样本的 heritage+full 阶段匹配 |
| **预计测试数** | 15-20 |

#### Step 5.2 — 多架构测试

| 项目 | 说明 |
|---|---|
| **内容** | ARM, MIPS, x86-64, PowerPC 架构的反编译测试 |
| **测试** | test_multiarch.py |
| **预计测试数** | 20-30 |

#### Step 5.3 — 输出一致性 Diff

| 项目 | 说明 |
|---|---|
| **内容** | 同一二进制，C++ 和 Python 反编译输出逐行比对 |
| **测试** | test_output_diff.py |
| **预计测试数** | 10-20 |

**Phase 5 总计**: ~45-70 个测试
**完成标志**: Python 输出与 C++ 输出在所有测试语料上完全一致

---

## 执行顺序与依赖关系

```
Phase 0 (测试债务) ─────────────────────────────────────────┐
  Step 0.1 Core层 ──→ Step 0.2 IR层 ──→ Step 0.3 DB层      │
  Step 0.4 Transform层 ──→ Step 0.5 Output层                │
                                                              ▼
Phase 1 (架构自举) ◄──────────────────────────────── Phase 0 完成
  Step 1.1 SleighArch ──→ Step 1.2 InjectSleigh              │
  Step 1.3 PcodeCompile ──→ Step 1.4 RawArch/XmlArch         │
  Step 1.5 端到端独立反编译                                    │
                  │                                            │
                  ▼                                            ▼
Phase 2 (CLI) ◄── Phase 1            Phase 3 (功能补全) ◄── Phase 1
  Step 2.1 Data ──→ 2.2 Commands       Step 3.1 PrintJava
                                        Step 3.2 CodeData
                  │                     Step 3.3 Signature
                  ▼                            │
Phase 4 (Ghidra协议) ◄── Phase 1              │
  Step 4.1 后端代理 ──→ 4.2 Encode ──→ 4.3 E2E │
                                                ▼
Phase 5 (全面验证) ◄── Phase 0+1+2+3+4 全部完成
  Step 5.1 Bridge扩展 ──→ 5.2 多架构 ──→ 5.3 Diff
```

## 工作量估算

| Phase | 新模块数 | 新测试文件数 | 预计测试数 | 预计工时 |
|---|---|---|---|---|
| Phase 0: 测试债务 | 0 | ~35 | 400-500 | 大 |
| Phase 1: 架构自举 | 5 | 6 | 55-75 | 大 |
| Phase 2: 反编译器CLI | 1(大) | 1 | 40-55 | 中 |
| Phase 3: 功能补全 | 4 | 4 | 45-60 | 中 |
| Phase 4: Ghidra协议 | 10(扩展) | 3 | 45-60 | 中 |
| Phase 5: 全面验证 | 0 | 3 | 45-70 | 中 |
| **总计** | **~20** | **~52** | **~630-820** | |

## 每步执行规范

每个 Step 执行时必须：
1. **阅读 C++ 源码** — 理解完整语义
2. **编写 Python 实现** — 类型注解 + 对齐 C++ 行为
3. **编写单元测试** — 覆盖正常路径 + 边界 + 错误处理
4. **运行测试** — `python -m pytest tests/test_xxx.py -v --timeout=120`
5. **运行全量测试** — `python -m pytest tests/ --timeout=120` 确保无回归
6. **更新 progress.md** — 标记完成状态
