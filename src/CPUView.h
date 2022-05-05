#pragma once
#include <QAbstractScrollArea>
#include <capstone.h>
#include <cstdint>

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