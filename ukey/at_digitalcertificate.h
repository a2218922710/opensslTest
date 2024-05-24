#ifndef AT_DIGITALCERTIFICATE_H
#define AT_DIGITALCERTIFICATE_H

#include <openssl/pkcs12.h>

#include <QSharedPointer>

namespace Adapts {
namespace UKey {

class SW_DigitalCertificatePrivate;
class SW_DigitalCertificate
{
    Q_DECLARE_PRIVATE(SW_DigitalCertificate)
public:
    SW_DigitalCertificate();
    ~SW_DigitalCertificate();
    /**
     * @brief GetCertificateList 获取当前系统中的数字证书列表
     * @return 返回数字证书列表
     */
    const QStringList GetCertificateList();

    /**
     * @brief VerifyCertificatePin 验证数字证书的PIN码
     * @param certificateName 数字证书名称
     * @param password 密码
     * @return 返回验证结果
     */
    bool VerifyCertificate(const QString& certificateName, const QString& password);

private:
    void ShowCertificateInfo(X509* cert);

private:
    QSharedPointer<SW_DigitalCertificatePrivate> d_ptr = nullptr;
};

}
}


#endif // AT_DIGITALCERTIFICATE_H
