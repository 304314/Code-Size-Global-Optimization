//===-- Sw64SelectionDAGInfo.cpp - Sw64 SelectionDAG Info ---------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the Sw64SelectionDAGInfo class.
//
//===----------------------------------------------------------------------===//

#include "Sw64TargetMachine.h"
using namespace llvm;

#define DEBUG_TYPE "sw_64-selectiondag-info"

SDValue Sw64SelectionDAGInfo::EmitTargetCodeForMemcpy(
    SelectionDAG &DAG, const SDLoc &dl, SDValue Chain, SDValue Dst, SDValue Src,
    SDValue Size, Align Alignment, bool isVolatile, bool AlwaysInline,
    MachinePointerInfo DstPtrInfo, MachinePointerInfo SrcPtrInfo) const {
  unsigned SizeBitWidth = Size.getValueSizeInBits();
  // Call __memcpy_4 if the src, dst and size are all 4 byte aligned.
  if (!AlwaysInline && Alignment >= Align(4) &&
      DAG.MaskedValueIsZero(Size, APInt(SizeBitWidth, 3))) {
    const TargetLowering &TLI = *DAG.getSubtarget().getTargetLowering();
    TargetLowering::ArgListTy Args;
    TargetLowering::ArgListEntry Entry;
    Entry.Ty = DAG.getDataLayout().getIntPtrType(*DAG.getContext());
    Entry.Node = Dst;
    Args.push_back(Entry);
    Entry.Node = Src;
    Args.push_back(Entry);
    Entry.Node = Size;
    Args.push_back(Entry);

    TargetLowering::CallLoweringInfo CLI(DAG);
    CLI.setDebugLoc(dl)
        .setChain(Chain)
        .setLibCallee(TLI.getLibcallCallingConv(RTLIB::MEMCPY),
                      Type::getVoidTy(*DAG.getContext()),
                      DAG.getExternalSymbol(
                          "memcpy", TLI.getPointerTy(DAG.getDataLayout())),
                      std::move(Args))
        .setDiscardResult();

    std::pair<SDValue, SDValue> CallResult = TLI.LowerCallTo(CLI);
    return CallResult.second;
  }

  // Otherwise have the target-independent code call memcpy.
  return SDValue();
}
