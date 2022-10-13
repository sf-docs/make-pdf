# Отсутствие проверки целостности приложения

<table class='noborder'>
    <colgroup>
      <col/>
      <col/>
    </colgroup>
    <tbody>
      <tr>
        <td rowspan="2"><img src="../../../img/defekt_srednij.png"/></td>
        <td>Критичность:<strong> СРЕДНЯЯ</strong></td>
      </tr>
      <tr>
        <td>Способ обнаружения:<strong> IAST</strong></td>
      </tr>
    </tbody>
</table>

## Описание

Одним из векторов атаки на мобильные приложения является так называемый **code tampering** — изменение кода приложения. Злоумышленники могут изменять код для получения преимуществ в ходе работы приложения, включения платных возможностей, отключения рекламы и различных проверок, распространения зловредного кода вместе с приложением через альтернативные площадки дистрибуции.

## Рекомендации

Чтобы усложнить модификацию кода приложения разработчики могут воспользоваться механизмом проверки подписи приложения во время его работы. С помощью объекта класса `PackageManaer` можно получить хеш сертификата, которым было подписано приложение и сравнить его с некоторым проверочным значением. Если значения совпадают, то приложение не было переподписано. Начиная с 28 API у `PackageManager`, доступен метод `hasSigningCertificate`, который проверяет совпадение хеша сертификата подписи с байтовым массивом.

**Пример кода проверки:**

    public boolean checkSign(String crt) {

        PackageManager pm = getPackageManager();
        String sign = crt.replace(":", "");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            return pm.hasSigningCertificate(getPackageName(), hexToByte(sign), PackageManager.CERT_INPUT_SHA256);
        } else {
            try {
                Signature signature = pm.getPackageInfo(getPackageName(), PackageManager.GET_SIGNATURES).signatures[0];
                byte[] pkgSign = MessageDigest.getInstance("SHA-256").digest(signature.toByteArray());
                return Arrays.equals(hexToByte(sign), pkgSign);

            } catch (PackageManager.NameNotFoundException | NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
        return false;
    }
 
Для получения хеша сертификата подписи релизной версии приложения можно использовать утилиту **keytool**:

    keytool -list -v -keystore sign_key.jks -alias key0 -storepass 123456 -keypass 123456

здесь `sign_key.jks` — файл с ключом подписи, `key0` — имя алиаса, `storepass` и `keypass` — пароли хранилища и ключа соответственно.

### Некоторые замечания:

Не стоит делать единственный метод с названием `checkSign()` или подобным, так как злоумышленник все-равно будет менять код — ему ничего не стоит заставить данный метод возвращать нужное значение. Проверку подписи лучше всего организовать многоступенчато в разных местах приложения, в том числе и в нативном коде.

Хорошим способом защиты является проверка подписи на стороне сервера, при этом следует помнить, что сами запросы также легко подделать, поэтому необходимо продумать механизм аутентификации проверочных запросов к серверу.

## Ссылки

1. [Подделка подписи Android-приложения и её проверка | OTUS](https://otus.ru/nest/post/858/) 

2. [GitHub - DimaKoz/stunning-signature: Native Signature Verification For Android (with example)](https://github.com/DimaKoz/stunning-signature) 

3. [Simple Android signature check. Please note: This was created in 2013, not actively maintained and may not be compatible with the latest Android versions. It's not particularly difficult for an attacker to decompile an .apk, find this tamper check, replace the APP_SIGNATURE with theirs and rebuild (or use method hooking to return true from `validateAppSignature()`). It'll make the task of running the .apk unsigned or with edited code slightly more time-consuming and hopefully reduce the effectiveness of automated attacker. But it's not bulletproof.](https://gist.github.com/scottyab/b849701972d57cf9562e) 

4. [owasp-mstg/0x05i-Testing-Code-Quality-and-Build-Settings.md at master · OWASP/owasp-mstg](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md) 