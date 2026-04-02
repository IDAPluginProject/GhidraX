"""
universalAction() pipeline wiring + buildDefaultGroups().
Corresponds to the end of coreaction.cc.
"""
from __future__ import annotations
from ghidra.transform.action import (
    Action, ActionGroup, ActionRestartGroup, ActionPool, ActionDatabase,
)
from ghidra.transform.coreaction import *
from ghidra.transform.coreaction2 import *

# Import all available rules
from ghidra.transform.ruleaction import *
from ghidra.transform.rules_compare import *
from ghidra.transform.rules_shift_compare import *
from ghidra.transform.rules_bitcount import *
from ghidra.transform.rules_zerocomp import *
from ghidra.transform.rules_extension import *
from ghidra.transform.rules_piece import *
from ghidra.transform.rules_misc import *
from ghidra.transform.rules_boollogic import *
from ghidra.transform.rules_signmod import *
from ghidra.transform.rules_phi_float import *
from ghidra.transform.rules_divopt import *
from ghidra.transform.rules_pointer import *
from ghidra.transform.rules_subvar import *


def universalAction(allacts: ActionDatabase, conf) -> None:
    """Construct the universal Action containing all possible components.

    Mirrors ActionDatabase::universalAction() in coreaction.cc.
    """
    stackspace = conf.getStackSpace() if conf is not None else None

    act = ActionRestartGroup(Action.rule_onceperfunc, "universal", 1)
    allacts.registerAction("universal", act)

    act.addAction(ActionStart("base"))
    act.addAction(ActionConstbase("base"))
    act.addAction(ActionNormalizeSetup("normalanalysis"))
    act.addAction(ActionDefaultParams("base"))
    act.addAction(ActionExtraPopSetup("base", stackspace))
    act.addAction(ActionPrototypeTypes("protorecovery"))
    act.addAction(ActionFuncLink("protorecovery"))
    act.addAction(ActionFuncLinkOutOnly("noproto"))

    # --- fullloop ---
    actfullloop = ActionGroup(Action.rule_repeatapply, "fullloop")

    # --- mainloop ---
    actmainloop = ActionGroup(Action.rule_repeatapply, "mainloop")
    actmainloop.addAction(ActionUnreachable("base"))
    actmainloop.addAction(ActionVarnodeProps("base"))
    actmainloop.addAction(ActionHeritage("base"))
    actmainloop.addAction(ActionParamDouble("protorecovery"))
    actmainloop.addAction(ActionSegmentize("base"))
    actmainloop.addAction(ActionInternalStorage("base"))
    actmainloop.addAction(ActionForceGoto("blockrecovery"))
    actmainloop.addAction(ActionDirectWrite("protorecovery_a", True))
    actmainloop.addAction(ActionDirectWrite("protorecovery_b", False))
    actmainloop.addAction(ActionActiveParam("protorecovery"))
    actmainloop.addAction(ActionReturnRecovery("protorecovery"))
    actmainloop.addAction(ActionRestrictLocal("localrecovery"))
    actmainloop.addAction(ActionDeadCode("deadcode"))
    actmainloop.addAction(ActionDynamicMapping("dynamic"))
    actmainloop.addAction(ActionRestructureVarnode("localrecovery"))
    actmainloop.addAction(ActionSpacebase("base"))
    actmainloop.addAction(ActionNonzeroMask("analysis"))
    actmainloop.addAction(ActionInferTypes("typerecovery"))

    # --- stackstall (contains oppool1) ---
    actstackstall = ActionGroup(Action.rule_repeatapply, "stackstall")

    actprop = ActionPool(Action.rule_repeatapply, "oppool1")
    actprop.addRule(RuleEarlyRemoval("deadcode"))
    actprop.addRule(RuleTermOrder("analysis"))
    actprop.addRule(RuleSelectCse("analysis"))
    actprop.addRule(RuleCollectTerms("analysis"))
    actprop.addRule(RulePullsubMulti("analysis"))
    actprop.addRule(RulePullsubIndirect("analysis"))
    actprop.addRule(RulePushMulti("nodejoin"))
    actprop.addRule(RuleSborrow("analysis"))
    actprop.addRule(RuleScarry("analysis"))
    actprop.addRule(RuleIntLessEqual("analysis"))
    actprop.addRule(RuleTrivialArith("analysis"))
    actprop.addRule(RuleTrivialBool("analysis"))
    actprop.addRule(RuleTrivialShift("analysis"))
    actprop.addRule(RuleSignShift("analysis"))
    actprop.addRule(RuleTestSign("analysis"))
    actprop.addRule(RuleIdentityEl("analysis"))
    actprop.addRule(RuleOrMask("analysis"))
    actprop.addRule(RuleAndMask("analysis"))
    actprop.addRule(RuleOrConsume("analysis"))
    actprop.addRule(RuleOrCollapse("analysis"))
    actprop.addRule(RuleAndOrLump("analysis"))
    actprop.addRule(RuleShiftBitops("analysis"))
    actprop.addRule(RuleRightShiftAnd("analysis"))
    actprop.addRule(RuleNotDistribute("analysis"))
    actprop.addRule(RuleHighOrderAnd("analysis"))
    actprop.addRule(RuleAndDistribute("analysis"))
    actprop.addRule(RuleAndCommute("analysis"))
    actprop.addRule(RuleAndPiece("analysis"))
    actprop.addRule(RuleAndZext("analysis"))
    actprop.addRule(RuleAndCompare("analysis"))
    actprop.addRule(RuleDoubleSub("analysis"))
    actprop.addRule(RuleDoubleShift("analysis"))
    actprop.addRule(RuleDoubleArithShift("analysis"))
    actprop.addRule(RuleConcatShift("analysis"))
    actprop.addRule(RuleLeftRight("analysis"))
    actprop.addRule(RuleShiftCompare("analysis"))
    actprop.addRule(RuleShift2Mult("analysis"))
    actprop.addRule(RuleShiftPiece("analysis"))
    actprop.addRule(RuleMultiCollapse("analysis"))
    actprop.addRule(RuleIndirectCollapse("analysis"))
    actprop.addRule(Rule2Comp2Mult("analysis"))
    actprop.addRule(RuleSub2Add("analysis"))
    actprop.addRule(RuleCarryElim("analysis"))
    actprop.addRule(RuleBxor2NotEqual("analysis"))
    actprop.addRule(RuleLess2Zero("analysis"))
    actprop.addRule(RuleLessEqual2Zero("analysis"))
    actprop.addRule(RuleSLess2Zero("analysis"))
    actprop.addRule(RuleEqual2Zero("analysis"))
    actprop.addRule(RuleEqual2Constant("analysis"))
    actprop.addRule(RuleThreeWayCompare("analysis"))
    actprop.addRule(RuleXorCollapse("analysis"))
    actprop.addRule(RuleAddMultCollapse("analysis"))
    actprop.addRule(RuleCollapseConstants("analysis"))
    actprop.addRule(RuleTransformCpool("analysis"))
    actprop.addRule(RulePropagateCopy("analysis"))
    actprop.addRule(RuleZextEliminate("analysis"))
    actprop.addRule(RuleSlessToLess("analysis"))
    actprop.addRule(RuleZextSless("analysis"))
    actprop.addRule(RuleBitUndistribute("analysis"))
    actprop.addRule(RuleBooleanUndistribute("analysis"))
    actprop.addRule(RuleBooleanDedup("analysis"))
    actprop.addRule(RuleBoolZext("analysis"))
    actprop.addRule(RuleBooleanNegate("analysis"))
    actprop.addRule(RuleLogic2Bool("analysis"))
    actprop.addRule(RuleSubExtComm("analysis"))
    actprop.addRule(RuleSubCommute("analysis"))
    actprop.addRule(RuleConcatCommute("analysis"))
    actprop.addRule(RuleConcatZext("analysis"))
    actprop.addRule(RuleZextCommute("analysis"))
    actprop.addRule(RuleZextShiftZext("analysis"))
    actprop.addRule(RuleShiftAnd("analysis"))
    actprop.addRule(RuleConcatZero("analysis"))
    actprop.addRule(RuleConcatLeftShift("analysis"))
    actprop.addRule(RuleSubZext("analysis"))
    actprop.addRule(RuleSubCancel("analysis"))
    actprop.addRule(RuleShiftSub("analysis"))
    actprop.addRule(RuleHumptyDumpty("analysis"))
    actprop.addRule(RuleDumptyHump("analysis"))
    actprop.addRule(RuleHumptyOr("analysis"))
    actprop.addRule(RuleNegateIdentity("analysis"))
    actprop.addRule(RuleSubNormal("analysis"))
    actprop.addRule(RulePositiveDiv("analysis"))
    actprop.addRule(RuleDivTermAdd("analysis"))
    actprop.addRule(RuleDivTermAdd2("analysis"))
    actprop.addRule(RuleDivOpt("analysis"))
    actprop.addRule(RuleSignForm("analysis"))
    actprop.addRule(RuleSignForm2("analysis"))
    actprop.addRule(RuleSignDiv2("analysis"))
    actprop.addRule(RuleDivChain("analysis"))
    actprop.addRule(RuleSignNearMult("analysis"))
    actprop.addRule(RuleModOpt("analysis"))
    actprop.addRule(RuleSignMod2nOpt("analysis"))
    actprop.addRule(RuleSignMod2nOpt2("analysis"))
    actprop.addRule(RuleSignMod2Opt("analysis"))
    actprop.addRule(RuleSwitchSingle("analysis"))
    actprop.addRule(RuleCondNegate("analysis"))
    actprop.addRule(RuleBoolNegate("analysis"))
    actprop.addRule(RuleLessEqual("analysis"))
    actprop.addRule(RuleLessNotEqual("analysis"))
    actprop.addRule(RuleLessOne("analysis"))
    actprop.addRule(RuleRangeMeld("analysis"))
    actprop.addRule(RuleFloatRange("analysis"))
    actprop.addRule(RulePiece2Zext("analysis"))
    actprop.addRule(RulePiece2Sext("analysis"))
    actprop.addRule(RulePopcountBoolXor("analysis"))
    actprop.addRule(RuleXorSwap("analysis"))
    actprop.addRule(RuleLzcountShiftBool("analysis"))
    actprop.addRule(RuleFloatSign("analysis"))
    actprop.addRule(RuleOrCompare("analysis"))
    actprop.addRule(RuleSubvarAnd("subvar"))
    actprop.addRule(RuleSubvarSubpiece("subvar"))
    actprop.addRule(RuleSplitFlow("subvar"))
    actprop.addRule(RulePtrFlow("subvar", conf))
    actprop.addRule(RuleSubvarCompZero("subvar"))
    actprop.addRule(RuleSubvarShift("subvar"))
    actprop.addRule(RuleSubvarZext("subvar"))
    actprop.addRule(RuleSubvarSext("subvar"))
    actprop.addRule(RuleNegateNegate("analysis"))
    actprop.addRule(RuleConditionalMove("conditionalexe"))
    actprop.addRule(RuleOrPredicate("conditionalexe"))
    actprop.addRule(RuleFuncPtrEncoding("analysis"))
    actprop.addRule(RuleSubfloatConvert("floatprecision"))
    actprop.addRule(RuleFloatCast("floatprecision"))
    actprop.addRule(RuleIgnoreNan("floatprecision"))
    actprop.addRule(RuleUnsigned2Float("analysis"))
    actprop.addRule(RuleInt2FloatCollapse("analysis"))
    actprop.addRule(RulePtraddUndo("typerecovery"))
    actprop.addRule(RulePtrsubUndo("typerecovery"))
    actprop.addRule(RuleSegment("segment"))
    actprop.addRule(RulePiecePathology("protorecovery"))
    actprop.addRule(RuleDoubleLoad("doubleload"))
    actprop.addRule(RuleDoubleStore("doubleprecis"))
    actprop.addRule(RuleDoubleIn("doubleprecis"))
    actprop.addRule(RuleDoubleOut("doubleprecis"))
    # Add CPU-specific / dynamic rules from architecture (C++ extra_pool_rules)
    if conf is not None and hasattr(conf, 'extra_pool_rules'):
        for dynrule in conf.extra_pool_rules:
            actprop.addRule(dynrule)
        conf.extra_pool_rules.clear()

    actstackstall.addAction(actprop)
    actstackstall.addAction(ActionLaneDivide("base"))
    actstackstall.addAction(ActionMultiCse("analysis"))
    actstackstall.addAction(ActionShadowVar("analysis"))
    actstackstall.addAction(ActionDeindirect("deindirect"))
    actstackstall.addAction(ActionStackPtrFlow("stackptrflow", stackspace))
    actmainloop.addAction(actstackstall)

    actmainloop.addAction(ActionRedundBranch("deadcontrolflow"))
    actmainloop.addAction(ActionBlockStructure("blockrecovery"))
    actmainloop.addAction(ActionConstantPtr("typerecovery"))

    # oppool2
    actprop2 = ActionPool(Action.rule_repeatapply, "oppool2")
    actprop2.addRule(RulePushPtr("typerecovery"))
    actprop2.addRule(RuleStructOffset0("typerecovery"))
    actprop2.addRule(RulePtrArith("typerecovery"))
    actprop2.addRule(RuleLoadVarnode("stackvars"))
    actprop2.addRule(RuleStoreVarnode("stackvars"))
    actmainloop.addAction(actprop2)

    actmainloop.addAction(ActionDeterminedBranch("unreachable"))
    actmainloop.addAction(ActionUnreachable("unreachable"))
    actmainloop.addAction(ActionNodeJoin("nodejoin"))
    actmainloop.addAction(ActionConditionalExe("conditionalexe"))
    actmainloop.addAction(ActionConditionalConst("analysis"))

    actfullloop.addAction(actmainloop)
    actfullloop.addAction(ActionLikelyTrash("protorecovery"))
    actfullloop.addAction(ActionDirectWrite("protorecovery_a", True))
    actfullloop.addAction(ActionDirectWrite("protorecovery_b", False))
    actfullloop.addAction(ActionDeadCode("deadcode"))
    actfullloop.addAction(ActionDoNothing("deadcontrolflow"))
    actfullloop.addAction(ActionSwitchNorm("switchnorm"))
    actfullloop.addAction(ActionReturnSplit("returnsplit"))
    actfullloop.addAction(ActionUnjustifiedParams("protorecovery"))
    actfullloop.addAction(ActionStartTypes("typerecovery"))
    actfullloop.addAction(ActionActiveReturn("protorecovery"))

    act.addAction(actfullloop)
    act.addAction(ActionMappedLocalSync("localrecovery"))
    act.addAction(ActionStartCleanUp("cleanup"))

    # cleanup pool
    actcleanup = ActionPool(Action.rule_repeatapply, "cleanup")
    actcleanup.addRule(RuleMultNegOne("cleanup"))
    actcleanup.addRule(RuleAddUnsigned("cleanup"))
    actcleanup.addRule(Rule2Comp2Sub("cleanup"))
    actcleanup.addRule(RuleDumptyHumpLate("cleanup"))
    actcleanup.addRule(RuleSubRight("cleanup"))
    actcleanup.addRule(RuleFloatSignCleanup("cleanup"))
    actcleanup.addRule(RuleExpandLoad("cleanup"))
    actcleanup.addRule(RulePtrsubCharConstant("cleanup"))
    actcleanup.addRule(RuleExtensionPush("cleanup"))
    actcleanup.addRule(RulePieceStructure("cleanup"))
    actcleanup.addRule(RuleSplitCopy("splitcopy"))
    actcleanup.addRule(RuleSplitLoad("splitpointer"))
    actcleanup.addRule(RuleSplitStore("splitpointer"))
    actcleanup.addRule(RuleStringCopy("constsequence"))
    actcleanup.addRule(RuleStringStore("constsequence"))
    act.addAction(actcleanup)

    act.addAction(ActionPreferComplement("blockrecovery"))
    act.addAction(ActionStructureTransform("blockrecovery"))
    act.addAction(ActionNormalizeBranches("normalizebranches"))
    act.addAction(ActionAssignHigh("merge"))
    act.addAction(ActionMergeRequired("merge"))
    act.addAction(ActionMarkExplicit("merge"))
    act.addAction(ActionMarkImplied("merge"))
    act.addAction(ActionMergeMultiEntry("merge"))
    act.addAction(ActionMergeCopy("merge"))
    act.addAction(ActionDominantCopy("merge"))
    act.addAction(ActionDynamicSymbols("dynamic"))
    act.addAction(ActionMarkIndirectOnly("merge"))
    act.addAction(ActionMergeAdjacent("merge"))
    act.addAction(ActionMergeType("merge"))
    act.addAction(ActionHideShadow("merge"))
    act.addAction(ActionCopyMarker("merge"))
    act.addAction(ActionOutputPrototype("localrecovery"))
    act.addAction(ActionInputPrototype("fixateproto"))
    act.addAction(ActionMapGlobals("fixateglobals"))
    act.addAction(ActionDynamicSymbols("dynamic"))
    act.addAction(ActionNameVars("merge"))
    act.addAction(ActionSetCasts("casts"))
    act.addAction(ActionFinalStructure("blockrecovery"))
    act.addAction(ActionPrototypeWarnings("protorecovery"))
    act.addAction(ActionStop("base"))


def buildDefaultGroups(allacts: ActionDatabase) -> None:
    """Set up descriptions of preconfigured root Actions.

    C++ ref: ``ActionDatabase::buildDefaultGroups`` in coreaction.cc
    """
    if getattr(allacts, '_isDefaultGroups', False):
        return
    if hasattr(allacts, '_groupmap'):
        allacts._groupmap.clear()

    decompile = [
        "base", "protorecovery", "protorecovery_a", "deindirect", "localrecovery",
        "deadcode", "typerecovery", "stackptrflow",
        "blockrecovery", "stackvars", "deadcontrolflow", "switchnorm",
        "cleanup", "splitcopy", "splitpointer", "merge", "dynamic", "casts", "analysis",
        "fixateglobals", "fixateproto", "constsequence",
        "segment", "returnsplit", "nodejoin", "doubleload", "doubleprecis",
        "unreachable", "subvar", "floatprecision",
        "conditionalexe",
    ]
    allacts.setGroup("decompile", decompile)

    jumptab = [
        "base", "noproto", "localrecovery", "deadcode", "stackptrflow",
        "stackvars", "analysis", "segment", "subvar", "normalizebranches", "conditionalexe",
    ]
    allacts.setGroup("jumptable", jumptab)

    normalize = [
        "base", "protorecovery", "protorecovery_b", "deindirect", "localrecovery",
        "deadcode", "stackptrflow", "normalanalysis",
        "stackvars", "deadcontrolflow", "analysis", "fixateproto", "nodejoin",
        "unreachable", "subvar", "floatprecision", "normalizebranches",
        "conditionalexe",
    ]
    allacts.setGroup("normalize", normalize)

    paramid = [
        "base", "protorecovery", "protorecovery_b", "deindirect", "localrecovery",
        "deadcode", "typerecovery", "stackptrflow", "siganalysis",
        "stackvars", "deadcontrolflow", "analysis", "fixateproto",
        "unreachable", "subvar", "floatprecision",
        "conditionalexe",
    ]
    allacts.setGroup("paramid", paramid)

    allacts.setGroup("register", ["base", "analysis", "subvar"])

    allacts.setGroup("firstpass", ["base"])

    allacts._isDefaultGroups = True
