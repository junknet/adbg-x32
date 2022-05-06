#include "MAPView.h"
#include <qnamespace.h>

MapView::MapView(QWidget *parent) : QListWidget()
{
    auto font = QFont("FiraCode", 8);
    setFont(font);
}

void MapView::setMap(QString &map)
{
    mapStr_ = map;
    clear();
    auto lines = mapStr_.split("\n", Qt::SkipEmptyParts);
    for (auto line : lines)
    {
        addItem(line);
    }
}
