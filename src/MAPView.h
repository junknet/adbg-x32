#pragma once

#include <QListWidget>

class MapView : public QListWidget
{
    Q_OBJECT
  public:
    explicit MapView(QWidget *parent = nullptr);
    ~MapView() override = default;

    void setMap(QString &map);

  private:
    QString mapStr_;
};