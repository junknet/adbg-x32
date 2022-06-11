#pragma once
#include <capstone.h>
#include <qcolor.h>
#include <qglobal.h>
#include <qlist.h>

#include <QAbstractScrollArea>
#include <QColor>
#include <cstdint>

#define MSG_STOP 1
#define MSG_CONTINUE 2
#define MSG_MAPS 3
#define MSG_REGS 4
#define MSG_STACK 5
#define MSG_DUMP 6
#define MSG_CPU 7
#define MSG_STEP 8
#define MSG_ADD_BP 9
#define MSG_DEL_BP 10

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
    void mousePressEvent(QMouseEvent *event) override;
    void keyPressEvent(QKeyEvent *event) override;
    void resizeEvent(QResizeEvent *) override;

    void jumpTo(uint32_t addr);

    void disassInstr();
    bool isThumbMode();
    void setCurrentPc(uint32_t value);
    void setProcessPaused(bool status);
    void setCurrentCPSR(uint32_t value);
    void setStartAddr(uint32_t addr);
    void setDebugFlag(bool flag);

    uint8_t data[0x400];
    uint32_t jump_addr_ = 0;
    uint32_t focusAddr;
    uint32_t focusIndex_;
    QList<uint32_t> bpList_;

  signals:
    void msg_cpu_sig(uint32_t addr);
    // void msg_add_bp_sig(uint32_t addr);
    // void msg_del_bp_sig(uint32_t addr);

  private:
    bool forceModeChange_ = false;
    bool forceThumbMode_ = true;
    int fontWidth_ = 0;
    int fontHeight_ = 0;

    int line1_ = 0;
    int line2_ = 0;
    int line3_ = 0;

    int line1_space = 10;
    int line2_space = 10;
    int line3_space = 10;

    int lineWidth_ = 0;
    bool debuged = false;
    bool screenScrolled = false;

    bool paused_ = false;
    csh handle_thumb;
    csh handle_arm;
    cs_insn *insn = nullptr;
    int count = 0;
    bool selected_ = false;
    int selectLine_ = 0;

    uint32_t pcValue_;
    uint32_t CPSR_;
    uint32_t startAddr_;
    uint32_t screenStartAddr;
    uint32_t screenEndAddr;
    uint32_t disStartAddr;
    uint32_t disEndAddr;

    QColor normal_color = QColor("#fcfcfc");
    QColor func_color = QColor("#f5f50e");
    QColor jump_color = QColor("#11f50d");
    QColor regs_color = QColor("#73adad");
    QColor focus_color = QColor("#414141");
    QColor addr_color = QColor("#a77cec");
    QColor pc_bgcolor = QColor("#bfb05100");
    QColor bp_bgcolor = QColor("#bfff0507");
    QColor bigbrack_color = QColor("#38d9f9");

    QList<QString> regsName_ = {"r0", "r1", "r2",  "r3",  "r4", "r5", "r6", "r7",
                                "r8", "r9", "r10", "r11", "ip", "sp", "lr", "pc"};
};

class DumpView : public QAbstractScrollArea
{
    Q_OBJECT

  public:
    explicit DumpView(QWidget *parent = nullptr);
    ~DumpView() override = default;

    // protected:
    void paintEvent(QPaintEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
    void keyPressEvent(QKeyEvent *event) override;
    void setDebugFlag(bool flag);
    void setStartAddr(uint32_t addr);

    uint8_t data[0x400];

  signals:
    void msg_dump_sig(uint32_t addr);

  private:
    int fontWidth_ = 0;
    int fontHeight_ = 0;

    int line1_ = 0;
    int line2_ = 0;
    int line3_ = 0;
    int lineWidth_ = 2;
    int maxLine_ = 0x400 / 16;
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
    void mousePressEvent(QMouseEvent *event) override;

    void setRegs(pt_regs reg);
    void setDebugFlag(bool flag);

  private:
    bool debuged = false;
    int fontWidth_ = 0;
    int fontHeight_ = 0;
    pt_regs lastRegs_;
    pt_regs currentRegs_;
    QList<int> regChanged;
    QList<int> flagChanged;
    QList<QString> regsName_ = {"r0", "r1", "r2",  "r3",  "r4",  "r5", "r6", "r7",
                                "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"};
    QList<QString> flagName_ = {"N", "Z", "C", "V", "Q"};
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