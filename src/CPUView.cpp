#include "CPUView.h"
#include "mainwindow.h"
#include <QAbstractScrollArea>
#include <QBrush>
#include <QDateTime>
#include <QInputDialog>
#include <QKeyEvent>
#include <QPainter>
#include <QScrollBar>
#include <boost/range/irange.hpp>
#include <capstone.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <qcolor.h>
#include <qdatetime.h>
#include <qdebug.h>
#include <qnamespace.h>

DisassView::DisassView(QWidget *parent) : QAbstractScrollArea()
{
    auto font = QFont("FiraCode", 8);
    auto metrics = QFontMetrics(font);
    fontWidth_ = metrics.horizontalAdvance('X');
    fontHeight_ = metrics.height();
    QAbstractScrollArea::setFont(font);

    line1_ = fontWidth_ * line1_space;
    line2_ = line1_ + fontWidth_ * line2_space;
    line3_ = line2_ + fontWidth_ * line3_space;

    lineWidth_ = fontWidth_;

    cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &handle_thumb);
    cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle_arm);
    cs_option(handle_thumb, CS_OPT_SKIPDATA, CS_OPT_ON);
    cs_option(handle_arm, CS_OPT_SKIPDATA, CS_OPT_ON);

    setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
}
void DisassView::disassInstr()
{
    cs_free(insn, count);
    if (currentPc_ & 1)
    {
        count = cs_disasm(handle_thumb, data, 0x400, startAddr_, 0, &insn);
    }
    else
    {
        count = cs_disasm(handle_arm, data, 0x400, startAddr_, 0, &insn);
    }
    disStartAddr = insn[0].address;
    disEndAddr = insn[count - 1].address;
    verticalScrollBar()->setMaximum(count - verticalScrollBar()->pageStep());

    if (jump_addr_)
    {
        focusAddr = jump_addr_;
        printf("jump_addr_:%x\n", jump_addr_);
        jump_addr_ = 0;
    }
    else
    {
        focusAddr = currentPc_;
        printf("pc:%x\n", currentPc_);
    }
    for (auto i : boost::irange(0, count))
    {
        auto ins_addr = insn[i].address;
        auto delta = ins_addr > focusAddr ? (ins_addr - focusAddr) : (focusAddr - ins_addr);
        if (delta < 4)
        {
            verticalScrollBar()->setValue(i);
            break;
        }
    }
}

void DisassView::setCurrentPc(uint32_t addr)
{
    currentPc_ = addr;
}

void DisassView::setStartAddr(uint32_t addr)
{
    startAddr_ = addr;
    printf("startAddr_:%x\n", startAddr_);
}

void DisassView::setDebugFlag(bool flag)
{
    debuged = flag;
}

void DisassView::paintEvent(QPaintEvent *event)
{
    if (!debuged)
    {
        return;
    }
    QSize areaSize = viewport()->size();
    auto offset = verticalScrollBar()->value();
    auto lines = areaSize.height() / fontHeight_;
    screenStartAddr = insn[offset].address;
    screenEndAddr = offset + lines > count ? insn[count - 1].address : insn[offset + lines].address;
    if (screenStartAddr == disStartAddr)
    {
        jumpTo(screenStartAddr);
    }
    if (screenEndAddr == disEndAddr)
    {
        printf("jumto screenEndAddr:%x\n ", screenEndAddr);
        jumpTo(screenEndAddr);
    }

    QPainter painter(viewport());
    // painter.setPen(QPen(Qt::blue));

    int line_y = 0;
    for (auto line : boost::irange(0, lines))
    {
        if (line + offset >= count)
        {
            break;
        }

        line_y = line * fontHeight_;
        auto line_addr = insn[offset + line].address;

        if (line_addr == currentPc_)
        {
            auto rect = QRectF(line1_, line_y, line2_ - line1_, fontHeight_);
            auto brush = QBrush(pc_bgcolor);
            painter.fillRect(rect, brush);

            auto pc_offset = 3;
            rect = QRectF(fontWidth_ * pc_offset, line_y, fontWidth_ * 2, fontHeight_);
            brush = QBrush(Qt::blue);
            painter.fillRect(rect, brush);
            painter.setPen(Qt::white);
            painter.drawText(fontWidth_ * pc_offset, line_y, fontWidth_ * 2, fontHeight_, Qt::AlignTop, "PC");
            painter.setPen(Qt::blue);
            painter.drawLine(fontWidth_ * (pc_offset + 2), line_y + fontHeight_ / 2, line1_, line_y + fontHeight_ / 2);
        }
        if (line_addr == focusAddr)
        {
            auto rect = QRectF(line1_, line_y, areaSize.width(), fontHeight_);
            auto brush = QBrush(focus_color);
            painter.fillRect(rect, brush);
        }

        auto addr = QString("%1").arg(line_addr, 8, 16, QLatin1Char('0'));
        painter.setPen(addr_color);
        painter.drawText(line1_ + lineWidth_, line_y, addr.length() * fontWidth_, fontHeight_, Qt::AlignTop, addr);

        auto mnemonic = QString(insn[line + offset].mnemonic);
        if (mnemonic.startsWith("b"))
        {
            painter.setPen(jump_color);
        }
        else if (mnemonic == "push" || mnemonic == "pop")
        {
            painter.setPen(func_color);
        }
        else
        {
            painter.setPen(normal_color);
        }
        painter.drawText(line2_ + lineWidth_, line_y, mnemonic.length() * fontWidth_, fontHeight_, Qt::AlignTop,
                         mnemonic);
        painter.setPen(normal_color);

        auto op_str = QString(insn[line + offset].op_str);
        if (op_str.startsWith("{"))
        {
            painter.setPen(bigbrack_color);
            painter.drawText(line3_ + lineWidth_, line_y, op_str.length() * fontWidth_, fontHeight_, 0, op_str);
        }
        else
        {
            auto ops = op_str.split(",", Qt::SkipEmptyParts);
            auto op_pos_x = 0;
            for (auto &op : ops)
            {
                auto op_trim = op.trimmed();
                painter.setPen(regsName_.contains(op_trim) ? regs_color : normal_color);
                painter.drawText(line3_ + lineWidth_ * (1 + op_pos_x), line_y, op.length() * fontWidth_, fontHeight_, 0,
                                 op);
                op_pos_x += op.length();
                if (op != ops[ops.length() - 1])
                {
                    painter.setPen(Qt::red);
                    painter.drawText(line3_ + lineWidth_ * (1 + op_pos_x), line_y, fontWidth_, fontHeight_, 0, ",");
                    op_pos_x++;
                }
            }
        }
    }

    painter.setPen(QPen(Qt::red));
    painter.drawLine(line1_, 0, line1_, areaSize.height());
    painter.drawLine(line2_, 0, line2_, areaSize.height());
    painter.drawLine(line3_, 0, line3_, areaSize.height());
}

void DisassView::keyPressEvent(QKeyEvent *event)
{
    if (event->key() == Qt::Key_G)
    {
        QString color_str;
        auto text = QInputDialog::getText(this, "", "");
        uint32_t addr = text.toUInt(nullptr, 16);
        if (!addr)
        {
            qDebug() << "addr toUInt error!";
            return;
        }
        jumpTo(addr);
    }
}

void DisassView::jumpTo(uint32_t addr)
{
    jump_addr_ = addr;
    char msg[5];
    msg[0] = MSG_CPU;
    *(uint32_t *)(msg + 1) = addr;
    socketClient_->write(msg, 5);
}

DumpView::DumpView(QWidget *parent) : QAbstractScrollArea()
{
    auto font = QFont("FiraCode", 8);
    auto metrics = QFontMetrics(font);
    fontWidth_ = metrics.horizontalAdvance('X');
    fontHeight_ = metrics.height();
    QAbstractScrollArea::setFont(font);

    line1_ = fontWidth_ * 15;
    line2_ = fontWidth_ * 25;
    verticalScrollBar()->setMaximum(maxLine_);
}

bool is_printable(uint8_t data)
{
    return (data >= 0x20) && (data <= 0x7E);
}

void DumpView::paintEvent(QPaintEvent *event)
{
    if (!debuged)
    {
        return;
    }

    QSize areaSize = viewport()->size();
    auto offset = verticalScrollBar()->value() * 16;
    auto max_line = areaSize.height() / fontHeight_ + 1;

    QPainter painter(viewport());
    for (auto line : boost::irange(0, max_line))
    {
        QString print_text;
        auto addr = QString("%1").arg(startAddr_ + offset + line * 16, 8, 16, QLatin1Char('0'));
        painter.drawText(0, line * fontHeight_, addr.length() * fontWidth_, fontHeight_, 0, addr);
        for (auto i : boost::irange(0, 16))
        {
            auto byte_data = (uint8_t)data[offset + line * 16 + i];
            print_text += (is_printable(byte_data) ? char(byte_data) : '.');
            auto draw_data = QString("%1").arg(byte_data, 2, 16, QLatin1Char('0'));
            painter.drawText((12 + i * 3) * fontWidth_, line * fontHeight_, draw_data.length() * fontWidth_,
                             fontHeight_, 0, draw_data);
        }
        painter.drawText((12 + 16 * 3) * fontWidth_, line * fontHeight_, print_text.length() * fontWidth_, fontHeight_,
                         0, print_text);
    }
    painter.setPen(QPen(QColor(106, 255, 124)));
    auto line = fontWidth_ * 11;
    auto step = fontWidth_ * 4 * 3;
    for (auto i : boost::irange(0, 5))
    {
        auto step_line = line + i * step;
        if (i > 0)
        {
            step_line += fontWidth_ * 0.5;
        }
        painter.drawLine(step_line, 0, step_line, areaSize.height());
    }
}
void DumpView::setDebugFlag(bool flag)
{
    debuged = flag;
}

void DumpView::setStartAddr(uint32_t addr)
{
    startAddr_ = addr;
}

RegsView::RegsView(QWidget *parent) : QAbstractScrollArea()
{
    auto font = QFont("FiraCode", 8);
    auto metrics = QFontMetrics(font);
    fontWidth_ = metrics.horizontalAdvance('X');
    fontHeight_ = metrics.height();
    QAbstractScrollArea::setFont(font);
}

void RegsView::setRegs(pt_regs reg)
{
    mRegs_ = reg;
}

void RegsView::setDebugFlag(bool flag)
{
    debuged = flag;
}

void RegsView::paintEvent(QPaintEvent *event)
{
    if (!debuged)
    {
        return;
    }
    QPainter painter(viewport());
    auto line = 0;
    auto reg_index = 0;
    uint32_t *reg_p = (uint32_t *)&mRegs_;
    for (auto reg_name : regsName_)
    {
        if (line == 13)
        {
            line += 2;
        }
        painter.drawText(0, line * fontHeight_, reg_name.length() * fontWidth_, fontHeight_, 0, reg_name);
        auto value = QString("%1").arg(*(reg_p + reg_index), 8, 16, QLatin1Char('0'));
        painter.drawText(fontWidth_ * 4, line * fontHeight_, value.length() * fontWidth_, fontHeight_, 0, value);
        line++;
        reg_index++;
    }

    line += 2;
    auto index = 0;
    for (auto flag_name : regFlag_)
    {
        painter.drawText(0, line * fontHeight_, flag_name.length() * fontWidth_, fontHeight_, 0, flag_name);
        auto value = QString("%1").arg((mRegs_.cpsr >> (31 - index)) & 1);
        painter.drawText(fontWidth_ * 4, line * fontHeight_, value.length() * fontWidth_, fontHeight_, 0, value);
        index++;
        line++;
    }
}

StackView::StackView(QWidget *parent) : QAbstractScrollArea()
{
    auto font = QFont("FiraCode", 8);
    auto metrics = QFontMetrics(font);
    fontWidth_ = metrics.horizontalAdvance('X');
    fontHeight_ = metrics.height();
    QAbstractScrollArea::setFont(font);
    verticalScrollBar()->setMaximum(maxLine_);
}

void StackView::paintEvent(QPaintEvent *event)
{
    if (!debuged)
    {
        return;
    }

    QSize areaSize = viewport()->size();
    auto offset = verticalScrollBar()->value() * 4;
    auto max_line = areaSize.height() / fontHeight_ + 1;

    QPainter painter(viewport());
    for (auto line : boost::irange(0, max_line))
    {
        QString print_text;
        auto addr = QString("%1").arg(startAddr_ + offset + line * 4, 8, 16, QLatin1Char('0'));
        painter.drawText(0, line * fontHeight_, addr.length() * fontWidth_, fontHeight_, 0, addr);
        auto byte_data = *(uint32_t *)&data[offset + line * 4];
        auto value = QString("%1").arg(byte_data, 8, 16, QLatin1Char('0'));
        painter.drawText(fontWidth_ * 10, line * fontHeight_, value.length() * fontWidth_, fontHeight_, 0, value);
    }
    // painter.setPen(QPen(QColor(106, 255, 124)));
    // auto line = fontWidth_ * 11;
    // auto step = fontWidth_ * 4 * 3;
    // for (auto i : boost::irange(0, 5))
    // {
    //     auto step_line = line + i * step;
    //     if (i > 0)
    //     {
    //         step_line += fontWidth_ * 0.5;
    //     }
    //     painter.drawLine(step_line, 0, step_line, areaSize.height());
    // }
}

void StackView::setSpValue(uint32_t value)
{
    spValue_ = value;
}

void StackView::setStartAddr(uint32_t addr)
{
    startAddr_ = addr;
}

void StackView::setDebugFlag(bool flag)
{
    debuged = flag;
}
