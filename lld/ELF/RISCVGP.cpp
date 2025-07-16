#include "lld/Common/ErrorHandler.h"
#include "lld/Common/Memory.h"
#include "OutputSections.h"
#include "SymbolTable.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/MapVector.h"
#include "llvm/Support/raw_ostream.h"

#include <map>
#include <string>
#include "llvm/Support/raw_ostream.h"

using namespace lld;
using namespace lld::elf;

namespace lld::elf {

// 计算gp最佳位置
uint64_t calculateRISCVGP(llvm::SmallVectorImpl<OutputSection *> &outputSections,
                          OutputSection *&beginSection) {
  SmallVector<StringRef, 0> dataStrs = {".data", ".sdata", ".sbss", ".bss"};
  SmallVector<OutputSection *, 0> dataOutputSections;
  SmallVector<StringRef, 0> inDataStr;


  uint64_t gpValue = 0x800;
  bool beginFlag = true;
// for (OutputSection *sec : outputSections)
//   llvm::errs() << "\n[DEBUG] " << __FILE__ << __LINE__ << ":" << "Section name: " << sec->name << "\n";

  for (OutputSection *sec : outputSections) {
    for (StringRef name : dataStrs) {
      if (name == sec->name) {
        dataOutputSections.push_back(sec);
        inDataStr.push_back(name);
        if (beginFlag) {
          beginSection = sec;
          beginFlag = false;
        }
        break;
      }
    }
  }

  if (inDataStr.empty())
  {
    llvm::errs() << "\n[DEBUG] " << __FILE__ << __LINE__ << ":" << " 默认GP为 0x" << llvm::format_hex(gpValue, 10) << "\n";
    return gpValue;
  }
  int n = inDataStr.size();
  std::vector<uint64_t> offsets(n);
  offsets[0] = 0;
  for (int i = 1; i < n; ++i)
    offsets[i] = offsets[i - 1] + dataOutputSections[i - 1]->size;

  std::map<std::string, uint64_t> strMap;
  for (int i = 0; i < n; ++i)
    strMap[inDataStr[i].str()] = offsets[i];

  struct LinkD {
    uint64_t position;
    int count;
    LinkD *next;
  };

  LinkD *head = new LinkD{0, 0, nullptr};

  for (OutputSection *osec : dataOutputSections) {
    SmallVector<InputSection *, 0> storage;
    for (InputSection *isec : getInputSections(*osec, storage)) {
      for (Relocation &reloc : isec->relocations) {
        Symbol *sym = reloc.sym;
        if (sym->kind() != Symbol::DefinedKind)
          continue;
        Defined *d = cast<Defined>(sym);
        uint64_t relativeAddr = strMap[d->section->name.str()] + d->value;

        for (LinkD *p = head;; p = p->next) {
          if (p->position == relativeAddr) {
            ++p->count;
            break;
          } else if (!p->next || relativeAddr < p->next->position) {
            p->next = new LinkD{relativeAddr, 1, p->next};
            break;
          }
        }
      }
    }
  }

  uint64_t maxpos = 0;
  int maxcount = 0;
  LinkD *start = head, *end = head;
  int count = 0;

  while (true) {
    if (end->next && (end->position - start->position) <= 0x1000) {
      end = end->next;
      count += end->count;
    } else {
      count -= start->count;
      start = start->next;
    }
    if (!end->next)
      break;
    if ((end->position - start->position) <= 0x1000 && count > maxcount) {
      maxcount = count;
      maxpos = start->position + 0x800;
      

    }
  }
  llvm::errs() << "\n[DEBUG] " << __FILE__ << __LINE__ << ":" << " 更改 GP 为 0x" << llvm::format_hex(maxpos, 10) << "\n";
  return maxpos;
}

} 
