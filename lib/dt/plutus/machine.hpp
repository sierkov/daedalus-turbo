/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_PLUTUS_MACHINE_HPP
#define DAEDALUS_TURBO_PLUTUS_MACHINE_HPP

#include <list>
#include <dt/plutus/builtins.hpp>
#include <dt/plutus/parser.hpp>

namespace daedalus_turbo::plutus {

    struct machine {
        term evaluate(const script &r, const term_list &args)
        {
            return _eval_program(r.program(), args);
        }
    private:
        enum class frame_type { compute, result };

        struct context {
            map<size_t, term_ptr> vars {};
            vector<term_ptr> builtin_binds {};

            void builtin_bind(const term_ptr &val)
            {
                builtin_binds.emplace_back(val);
            }

            void bind(const size_t var_idx, const term_ptr &val)
            {
                vars.emplace(var_idx, val);
            }

            term_ptr builtin_take()
            {
                if (!builtin_binds.empty()) {
                    auto val = std::move(builtin_binds.back());
                    builtin_binds.pop_back();
                    return val;
                }
                throw error("no bound variables found!");
            }
        };

        struct frame {
            frame_type type {};
            term_ptr expr {};
        };

        frame _compute_builtin(const size_t num_args, const builtin_any &f, context &ctx)
        {
            switch (num_args) {
                case 1: {
                    const auto arg1 = ctx.builtin_take();
                    return { frame_type::result, std::make_shared<term>(std::get<builtin_one_arg>(f)(*arg1)) };
                }
                case 2: {
                    const auto arg1 = ctx.builtin_take();
                    const auto arg2 = ctx.builtin_take();
                    return { frame_type::result, std::make_shared<term>(std::get<builtin_two_arg>(f)(*arg1, *arg2)) };
                }
                case 3: {
                    const auto arg1 = ctx.builtin_take();
                    const auto arg2 = ctx.builtin_take();
                    const auto arg3 = ctx.builtin_take();
                    return { frame_type::result, std::make_shared<term>(std::get<builtin_three_arg>(f)(*arg1, *arg2, *arg3)) };
                }
                case 6: {
                    const auto arg1 = ctx.builtin_take();
                    const auto arg2 = ctx.builtin_take();
                    const auto arg3 = ctx.builtin_take();
                    const auto arg4 = ctx.builtin_take();
                    const auto arg5 = ctx.builtin_take();
                    const auto arg6 = ctx.builtin_take();
                    return { frame_type::result, std::make_shared<term>(std::get<builtin_six_arg>(f)(*arg1, *arg2, *arg3, *arg4, *arg5, *arg6)) };
                }
                default: throw error("unsupported number of arguments: {}!", num_args);
            }
        }

        frame _compute(const builtin &b, context &ctx)
        {
            const auto &info = b.meta();
            return _compute_builtin(info.num_args, info.func, ctx);
        }

        frame _compute(const delay &d, context &)
        {
            return { frame_type::result, d.expr };
        }

        frame _compute(const force &f, context &ctx)
        {
            switch (f.expr->tag) {
                case term_tag::delay: return { frame_type::compute, std::get<delay>(f.expr->expr).expr };
                case term_tag::builtin: {
                    const auto &b = std::get<builtin>(f.expr->expr);
                    const auto &info = b.meta();
                    if (ctx.builtin_binds.size() >= info.num_args)
                        return _compute_builtin(info.num_args, info.func, ctx);
                    return { frame_type::compute, f.expr };
                }
                default: return { frame_type::compute, f.expr };
            }
        }

        frame _compute(const failure &, context &)
        {
            throw error("script failed");
        }

        frame _compute(const variable &v, context &ctx)
        {
            if (const auto val_it = ctx.vars.find(v.idx); val_it != ctx.vars.end()) [[likely]]
                return { frame_type::result, val_it->second };
            throw error("a referenced variable must bound first!");
        }

        frame _compute(const constant_list &cl, context &)
        {
            return { frame_type::result, std::make_shared<term>(term_tag::constant, cl) };
        }

        frame _compute(const apply &a, context &ctx)
        {
            switch (a.func->tag) {
                case term_tag::apply:
                    return { frame_type::compute, _compute(std::get<apply>(a.func->expr), ctx).expr };
                case term_tag::force:
                    return { frame_type::compute, _compute(std::get<force>(a.func->expr), ctx).expr };
                case term_tag::variable: {
                    const auto &v = std::get<variable>(a.func->expr);
                    ctx.bind(v.idx, a.arg);
                    break;
                }
                case term_tag::lambda: {
                    const auto &l = std::get<lambda>(a.func->expr);
                    ctx.bind(l.var_idx, a.arg);
                    break;
                }
                case term_tag::builtin: {
                    ctx.builtin_bind(a.arg);
                    break;
                }
                default: throw error("cannot apply to: {}", *a.func);
            }
            return { frame_type::compute, a.func };
        }

        frame _compute(const lambda &l, context &/*ctx*/)
        {
            return { frame_type::compute, l.expr };
        }

        frame _process_compute(const term &t, context &ctx)
        {
            logger::info("process_compute: {}", t.tag);
            return std::visit(
                [this, &ctx](const auto &val) {
                    return _compute(val, ctx);
                },
                t.expr
            );
        }

        /*frame _process_return() const
        {
        }*/

        term _eval_program(const term &program, const term_list &args)
        {
            std::list<frame> stack {};
            context ctx {};
            for (size_t i = 0; i < args.size(); ++i)
                ctx.bind(i, std::make_shared<term>(args[i]));
            stack.emplace_back(frame_type::compute, std::make_shared<term>(program));
            while (!stack.empty()) {
                auto fr = std::move(stack.back());
                stack.pop_back();
                switch (fr.type) {
                    case frame_type::compute:
                        stack.emplace_back(_process_compute(*fr.expr, ctx));
                        break;
                    case frame_type::result:
                        //stack.emplace_back(_process_return());
                        if (!stack.empty()) {
                            throw error("unsupported operation!");
                            //stack.emplace_back(_process_result(fr.term));
                        } else {
                            return *fr.expr;
                        }
                        break;
                    default:
                        throw error("unsupported frame type: {}!", static_cast<int>(fr.type));
                }
            }
            throw error("program evaluation didn't produce a result!");
        }
    };
}

#endif //DAEDALUS_TURBO_PLUTUS_MACHINE_HPP