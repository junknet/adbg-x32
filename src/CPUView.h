#pragma once
#include <QAbstractScrollArea>
#include <capstone.h>
#include <cstdint>
#include <qlist.h>

struct pt_regs
{
    uint32_t r0;
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint32_t r4;
    uint32_t r5;
    uint32_t r6;
    uint32_t r7;
    uint32_t r8;
    uint32_t r9;
    uint32_t r10;
    uint32_t r11;
    uint32_t r12;
    uint32_t sp;
    uint32_t lr;
    uint32_t pc;
    uint32_t cpsr;
    uint32_t orig_r0;
};

class DisassView : public QAbstractScrollArea
{
    Q_OBJECT
  public:
    explicit DisassView(QWidget *parent = nullptr);
    ~DisassView() override = default;

    // protected:
    void paintEvent(QPaintEvent *event) override;
    // void mousePressEvent(QMouseEvent *event) override;

    void disassInstr();
    void setCurrentPc(uint32_t addr);

    uint8_t data[0x3000];

  private:
    int fontWidth_ = 0;
    int fontHeight_ = 0;

    int line1_ = 0;
    int line2_ = 0;
    int line3_ = 0;
    int lineWidth_ = 2;

    csh handle;
    cs_insn *insn = nullptr;
    int count = 0;
    bool selected_ = false;
    int selectLine_ = 0;

    uint32_t currentPc_;
};

class DumpView : public QAbstractScrollArea
{
    Q_OBJECT

  public:
    explicit DumpView(QWidget *parent = nullptr);
    ~DumpView() override = default;

    // protected:
    void paintEvent(QPaintEvent *event) override;
    void setDebugFlag(bool flag);
    void setStartAddr(uint32_t addr);

    uint8_t data[0x3000];

  private:
    int fontWidth_ = 0;
    int fontHeight_ = 0;

    int line1_ = 0;
    int line2_ = 0;
    int line3_ = 0;
    int lineWidth_ = 2;
    int maxLine_ = 0x3000 / 16;
    uint32_t startAddr_;
    bool debuged = false;
};

class RegsView : public QAbstractScrollArea
{
    Q_OBJECT

  public:
    explicit RegsView(QWidget *parent = nullptr);
    ~RegsView() override = default;

    void paintEvent(QPaintEvent *event) override;

    void setRegs(pt_regs reg);
    void setDebugFlag(bool flag);

  private:
    int fontWidth_ = 0;
    int fontHeight_ = 0;
    pt_regs mRegs_;
    bool debuged = false;
    const QList<QString> regsName_ = {"r0", "r1", "r2",  "r3",  "r4",  "r5", "r6", "r7",
                                      "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"};
};

class StackView : public QAbstractScrollArea
{
    Q_OBJECT

  public:
    explicit StackView(QWidget *parent = nullptr);
    ~StackView() override = default;

    void paintEvent(QPaintEvent *event) override;
    void setSpValue(uint32_t value);
    void setStartAddr(uint32_t addr);
    void setDebugFlag(bool flag);

    uint8_t data[0x3000];

  private:
    int fontWidth_ = 0;
    int fontHeight_ = 0;
    bool debuged = false;
    int maxLine_ = 0x3000 / 4;
    uint32_t startAddr_;
    uint32_t spValue_;
};