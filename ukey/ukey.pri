isEmpty(UKEY_PRI_INCLUDE) {
UKEY_PRI_INCLUDE = 1

INCLUDEPATH += $$PWD/../openssl/lib/
DEPENDPATH += $$PWD/../openssl/lib/

INCLUDEPATH += $$PWD/../openssl/includefile/

HEADERS += $$files($$PWD/*.h, true)
SOURCES += $$files($$PWD/*.cpp, true)

win32:CONFIG(release, debug|release): LIBS += -L$$PWD/../openssl/lib/release/ -lssl
else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/../openssl/lib/debug/ -lssl

win32:CONFIG(release, debug|release): LIBS += -L$$PWD/../openssl/lib/release/ -lcrypto
else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/../openssl/lib/debug/ -lcrypto

}
