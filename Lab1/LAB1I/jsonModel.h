#ifndef JSONMODEL_H
#define JSONMODEL_H
#include "QDebug"
#include "QFile"
#include "QJsonArray"
#include "QJsonDocument"
#include "QJsonObject"
#include "QString"

class JsonModel {
 public:
  JsonModel(const QString key);
  QString key;
  QByteArray file;
  QJsonArray json;

  static const QString kFileName;
  const struct {
    QString login;
    QString pass;
    QString url;
  } fields = {"login", "pass", "url"};

  struct Row {
    QString url;
    QString login;
    QString pass;
  };

  QJsonArray readJson(QString key);

  static QByteArray readFile();
  void writeFile();
  void writeRowToJSON(Row row);

  Row getRow(int index);

  Row encrypt(Row row);
  Row decrypt(Row row);
};

#endif  // JSONMODEL_H
