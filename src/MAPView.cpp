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
        QString data;
        auto infos = line.split(" ", Qt::SkipEmptyParts);
        data += infos[0];
        data += "\t" + infos[1];
        if (infos.length() > 5)
            data += "\t" + infos[infos.length() - 1];
        addItem(data);
    }
}
