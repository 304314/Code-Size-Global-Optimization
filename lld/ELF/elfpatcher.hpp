#pragma once

#include <algorithm>
#include <cassert>
#include <cstring>
#include <elf.h>
#include <fstream>
#include <vector>
#include <iostream>

namespace csgo25 {
    using namespace std;

    class ELFPatcher {
    private:
        char *data;
        int current_section_num;
        int current_file_size;

        Elf32_Word raw_text_sec_index;
        vector<int> raw_func_starts;

        struct info {
            // 符号表信息
            Elf32_Sym *sym;
            // 对应的新代码段头
            Elf32_Shdr *sh;
            // 新代码段相对文件偏移
            Elf32_Addr foffset;
            // 对应的重定位段头, 可能没有
            Elf32_Shdr *relah;
            // 在段头表中的索引
            Elf32_Word index;
        };

        vector<info> func_info;

    public:
        explicit ELFPatcher(const char *objfile) {
            auto infile = ifstream(objfile, ios::binary | ios::ate);
            assert(infile);
            auto size = infile.tellg();
            current_file_size = size;
            infile.seekg(0, ios::beg);
            data = new char[size * 4];
            infile.read(data, size);
            current_section_num = get_sections().size();
        }

        ~ELFPatcher() {
            assert(data);
            delete[] data;
        }

        void patch_and_save(const char *objfile) {
            add_func_sections();
            add_rela_sections();
            update_symtab();
            update_elf_header();

            ofstream ofile(objfile, ios::binary);
            ofile.write(data, current_file_size);
            ofile.close();
        }

        void add_func_sections() {
            const auto &funcs = get_func_syms();

            if (funcs.empty())
                return;

            auto func_num = funcs.size();
            func_info.resize(func_num);
            assert(func_num >= 1);
            auto [raw_text_addr, raw_text_index] = get_text_sec();
            raw_text_sec_index = raw_text_index;

            auto raw_text_off = raw_text_addr->sh_offset;

            auto size = sizeof(Elf32_Shdr);
            auto prev_size = current_file_size;
            current_file_size += (func_num - 1) * size;

            for (int i = 0; i < func_num - 1; i++) {
                auto new_func_text_addr = reinterpret_cast<Elf32_Shdr *>(data + prev_size + size * i);
                memcpy(new_func_text_addr, raw_text_addr, size);
                func_info[i + 1] = info{
                    funcs[i + 1], new_func_text_addr, raw_text_off + funcs[i + 1]->st_value, nullptr,
                    static_cast<Elf32_Word>(current_section_num + i)
                };
            }
            func_info[0] = {funcs[0], raw_text_addr, raw_text_off, nullptr, raw_text_index};
            current_section_num += func_num - 1;

            // 向每个函数对应的代码段里写入信息
            // 由于rv指令定长, 无需考虑对齐

            for (auto &[func, fheader, foffset, _, _idx]: func_info) {
                // fheader->sh_name = func->st_name;
                // 新段名设置为.text后, 链接器会自动合并段
                fheader->sh_name = raw_text_addr->sh_name;
                fheader->sh_offset = foffset;
                fheader->sh_size = func->st_size;
            }
        }


        void add_rela_sections() {
            const auto &relas = get_relas();

            if (relas.empty())
                return;


            raw_func_starts.resize(func_info.size());
            for (int i = 0; i < raw_func_starts.size(); i++) {
                const auto &[f,ff,fff,ffff, fffff] = func_info[i];
                raw_func_starts[i] = f->st_value;
            }

            auto raw_rela_addr = get_rela_text_sec();
            func_info[0].relah = raw_rela_addr;
            auto last_rela_off = raw_rela_addr->sh_offset;

            raw_rela_addr->sh_name = func_info[0].sym->st_name;
            raw_rela_addr->sh_size = 0;
            raw_rela_addr->sh_info = func_info[0].index;

            for (auto rela: relas) {
                auto off = rela->r_offset;

                auto func_index = raw_func_starts.size() - 1;
                for (int i = 0; i < raw_func_starts.size(); i++) {
                    if (off < raw_func_starts[i]) {
                        func_index = i - 1;
                        break;
                    }
                }


                if (func_info[func_index].relah == nullptr) {
                    auto relah = reinterpret_cast<Elf32_Shdr *>(data + current_file_size);
                    memcpy(relah, raw_rela_addr, get_header()->e_shentsize);

                    relah->sh_name = func_info[func_index].sym->st_name;
                    relah->sh_offset = last_rela_off;
                    relah->sh_size = 0;
                    relah->sh_info = func_info[func_index].index;
                    func_info[func_index].relah = relah;

                    current_section_num++;
                    current_file_size += get_header()->e_shentsize;
                }

                rela->r_offset -= raw_func_starts[func_index];
                func_info[func_index].relah->sh_size += raw_rela_addr->sh_entsize;
                last_rela_off += raw_rela_addr->sh_entsize;
            }
        }

        void update_symtab() {
            for (auto &[sym, _sh, _fof, _rel, index]: func_info) {
                sym->st_value = 0;
                sym->st_shndx = index;
            }

            for (auto blk: get_basicblock_syms()) {
                auto off = blk->st_value;
                auto func_index = raw_func_starts.size() - 1;
                for (int i = 1; i < raw_func_starts.size(); i++) {
                    if (off < raw_func_starts[i]) {
                        func_index = i - 1;
                        break;
                    }
                }
                cout << __func__ << ": " << get_sym_name(blk) << ": " << blk->st_shndx << " -> " << func_index << ": "
                        << func_info[func_index].index << endl;
                blk->st_value -= raw_func_starts[func_index];
                blk->st_shndx = func_info[func_index].index;
            }
        }

        void update_elf_header() {
            get_header()->e_shnum = current_section_num;
        }


        Elf32_Ehdr *get_header() { return reinterpret_cast<Elf32_Ehdr *>(data); }

        vector<Elf32_Shdr *> get_sections() {
            auto header = get_header();
            auto sec_num = header->e_shnum;
            auto sec_off = header->e_shoff;
            auto sec_size = header->e_shentsize;
            vector<Elf32_Shdr *> secs;
            secs.reserve(sec_num);
            for (int i = 0; i < sec_num; i++) {
                secs.emplace_back(reinterpret_cast<Elf32_Shdr *>(data + sec_off + i * sec_size));
            }
            return secs;
        }

        tuple<Elf32_Shdr *, Elf32_Word> get_text_sec() {
            Elf32_Shdr *res = nullptr;
            Elf32_Word index = 0;
            const auto &secs = get_sections();
            for (int i = 0; i < secs.size(); i++) {
                auto psec = secs[i];
                // type为progbits且flag为ax
                if (psec->sh_type == SHT_PROGBITS && psec->sh_flags & SHF_ALLOC &&
                    psec->sh_flags & SHF_EXECINSTR) {
                    assert(!res && "multiple section with PROGBITS and AX found");
                    res = psec;
                    index = i;
                }
            }
            return {res, index};
        }

        Elf32_Shdr *get_rela_text_sec() {
            const auto secs = get_sections();
            auto [text_sec, _] = get_text_sec();
            auto text_sec_iter = find(secs.begin(), secs.end(), text_sec);
            assert(text_sec_iter != secs.end());
            auto text_sec_index = distance(secs.begin(), text_sec_iter);

            Elf32_Shdr *res = nullptr;
            for (auto psec: get_sections()) {
                // type为rela且info指向text索引
                if (psec->sh_type == SHT_RELA && psec->sh_info == text_sec_index) {
                    assert(!res &&
                        "multiple section with RELA and pointing to text section found");
                    res = psec;
                }
            }
            return res;
        }

        vector<Elf32_Rela *> get_relas() {
            auto rela_sec = get_rela_text_sec();

            if (!rela_sec)
                return {};

            auto rela_size = rela_sec->sh_size;
            auto rela_entsize = rela_sec->sh_entsize;
            auto rela_off = rela_sec->sh_offset;
            auto rela_num = rela_size / rela_entsize;
            vector<Elf32_Rela *> res(rela_num);
            for (int i = 0; i < rela_num; i++) {
                res[i] = reinterpret_cast<Elf32_Rela *>(data + rela_off + i * rela_entsize);
            }
            for (int i = 1; i < res.size(); i++) {
                assert(res[i-1]->r_offset <= res[i]->r_offset);
            }
            return res;
        }

        vector<Elf32_Rela> get_relas_value() {
            const auto &relas_addr = get_relas();
            vector<Elf32_Rela> res(relas_addr.size());
            for (auto i = 0; i < relas_addr.size(); i++) {
                res[i] = *relas_addr[i];
            }

            return res;
        }


        Elf32_Shdr *get_symtab_sec() {
            Elf32_Shdr *res = nullptr;
            for (auto psec: get_sections()) {
                // type为progbits且flag为ax
                if (psec->sh_type == SHT_SYMTAB) {
                    assert(!res && "multiple section with SYMTAB found");
                    res = psec;
                }
            }
            return res;
        }

        vector<Elf32_Sym *> get_func_syms() {
            auto symtab_sec = get_symtab_sec();
            auto syms_off = symtab_sec->sh_offset;
            auto syms_size = symtab_sec->sh_size;

            if (!syms_size)
                return {};

            auto syms_entsize = symtab_sec->sh_entsize;
            auto syms_num = syms_size / syms_entsize;
            vector<Elf32_Sym *> res;
            res.reserve(syms_num);
            for (int i = 0; i < syms_num; i++) {
                auto sym = reinterpret_cast<Elf32_Sym *>(data + syms_off + i * syms_entsize);
                if (sym->st_info & STT_FUNC) {
                    cout << __func__ << ": get function: " << get_sym_name(sym) << endl;
                    res.emplace_back(sym);
                }
            }

            // sort(res.begin(), res.end(), [](const Elf32_Sym *lhs, const Elf32_Sym *rhs) {
            //     cout << "lhs: " << lhs << ", rhs: " << rhs << endl;
            //     return lhs->st_value <= rhs->st_value;
            // });

            if (res.empty())
                return res;

            for (int i = 0; i < res.size() - 1; i++) {
                for (int j = 0; j < res.size() - i - 1; j++) {
                    auto lhs = res[j];
                    auto rhs = res[j + 1];

                    if (lhs->st_value > rhs->st_value) {
                        cout << "lhs: " << lhs << ", lhsv: " << lhs->st_value << ", rhs: " << rhs << ", rhsv: " << rhs->
                                st_value << endl;
                        swap(res[j], res[j + 1]);
                    }
                }
            }

            return res;
        }

        vector<Elf32_Sym *> get_basicblock_syms() {
            auto symtab_sec = get_symtab_sec();
            auto syms_off = symtab_sec->sh_offset;
            auto syms_size = symtab_sec->sh_size;
            auto syms_entsize = symtab_sec->sh_entsize;
            auto syms_num = syms_size / syms_entsize;

            vector<Elf32_Sym *> res;
            res.reserve(syms_num);

            for (auto i = 0; i < syms_num; i++) {
                auto sym = reinterpret_cast<Elf32_Sym *>(data + syms_off + i * syms_entsize);
                if (sym->st_shndx == raw_text_sec_index && !sym->st_info && string(get_sym_name(sym)).find(".LBB") ==
                    0) {
                    // string name = get_sym_name(sym);
                    // assert(name.find(".LBB") == 0 && name.data());
                    res.emplace_back(sym);
                }
            }

            sort(res.begin(), res.end(), [](const Elf32_Sym *lhs, const Elf32_Sym *rhs) {
                return lhs->st_value <= rhs->st_value;
            });
            return res;
        }

        char *get_sym_name(Elf32_Sym *sym) {
            Elf32_Shdr *strtab = get_sections()[get_header()->e_shstrndx];
            return data + strtab->sh_offset + sym->st_name;
        }
    };
}
