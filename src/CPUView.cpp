#include "CPUView.h"
#include "mainwindow.h"
#include <QAbstractScrollArea>
#include <QBrush>
#include <QPainter>
#include <QScrollBar>
#include <boost/range/irange.hpp>
#include <capstone.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <qcolor.h>
#include <qnamespace.h>

DisassView::DisassView(QWidget *parent) : QAbstractScrollArea()
{
    auto font = QFont("FiraCode", 8);
    auto metrics = QFontMetrics(font);
    fontWidth_ = metrics.horizontalAdvance('X');
    fontHeight_ = metrics.height();
    QAbstractScrollArea::setFont(font);
    line1_ = fontWidth_ * 15;
    line2_ = fontWidth_ * 25;

    cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &handle);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
}

void DisassView::disassInstr()
{
    cs_free(insn, count);
    count = cs_disasm(handle, data, 0x3000, currentPc_ & ~0xfff - 0x1000, 0, &insn);
    verticalScrollBar()->setMaximum(count);
    printf("pc:%x\n", currentPc_);
    for (auto i : boost::irange(0, count))
    {
        if (insn[i].address == (currentPc_ & ~0x1))
        {
            verticalScrollBar()->setValue(i - 10);
            break;
        }
    }
}

void DisassView::setCurrentPc(uint32_t addr)
{
    currentPc_ = addr;
}

void DisassView::paintEvent(QPaintEvent *event)
{
    QSize areaSize = viewport()->size();

    auto offset = verticalScrollBar()->value();
    auto item_count = areaSize.height() / fontHeight_ + 1;

    QPainter painter(viewport());
    // painter.setPen(QPen(Qt::blue));

    int row = 0;
    for (auto i : boost::irange(0, item_count))
    {
        if (i + offset >= count)
        {
            break;
        }

        if (selected_ && selectLine_ - offset == i)
        {
            painter.save();
            // painter.setPen(QPen(QColor(150, 55, 70)));
            auto rect = QRectF(0, i * fontHeight_, areaSize.width(), fontHeight_);
            auto brush = QBrush(QColor(150, 55, 70));
            painter.fillRect(rect, brush);
            // painter.fillRect(0, 0, areaSize.width(), fontHeight_);
            painter.restore();
        }

        row = i * fontHeight_;
        auto addr = QString("0x%1").arg(insn[i + offset].address, 8, 16, QLatin1Char('0'));
        painter.drawText(0, row, addr.length() * fontWidth_, fontHeight_, Qt::AlignTop, addr);

        auto mnemonic = QString(insn[i + offset].mnemonic);
        painter.drawText(line1_ + lineWidth_, row, mnemonic.length() * fontWidth_, fontHeight_, Qt::AlignTop, mnemonic);

        auto op_str = QString(insn[i + offset].op_str);
        painter.drawText(line2_ + lineWidth_, row, op_str.length() * fontWidth_, fontHeight_, 0, op_str);
    }
    painter.setPen(QPen(Qt::black));
    painter.drawLine(line1_, 0, line1_, areaSize.height());
    painter.drawLine(line2_, 0, line2_, areaSize.height());
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
        auto addr = QString("0x%1").arg(startAddr_ + offset + line * 16, 8, 16, QLatin1Char('0'));
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
    debuged = true;
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
    uint32_t *value_p = (uint32_t *)&mRegs_;
    for (auto reg_name : regsName_)
    {
        painter.drawText(0, line * fontHeight_, reg_name.length() * fontWidth_, fontHeight_, 0, reg_name);
        auto value = QString("%1").arg(*(value_p + line), 8, 16, QLatin1Char('0'));
        painter.drawText(fontWidth_ * 4, line * fontHeight_, value.length() * fontWidth_, fontHeight_, 0, value);
        line++;
    }
}
