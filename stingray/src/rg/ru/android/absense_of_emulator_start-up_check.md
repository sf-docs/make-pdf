# Отсутствие проверки на запуск на эмуляторе

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

Запуск и работа приложений в ОС без проверки окружения может нести значительные риски.

Злоумышленник или легальный пользователь могут запускать приложение на эмуляторе с целью создания фейковых аккаунтов, накруток различных показателей, исследования взаимодействия приложения с ОС и другими приложениями, а также исследования взаимодействия приложения по сети, в том числе с серверной частью (исследование API). Установка и работа в таком окружении значительно снижает безопасность данных пользователя и потенциально увеличивает риск финансовых и репутационных потерь для поставщика приложения.

Использование эмулятора зачастую противоречит политике и целям производителя приложения. В некоторых случаях установка на эмулятор производится с целью получения прямой выгоды пользователем или преимущества перед другими пользователями. Кроме того, исследование и использование приложений злоумышленниками в большинстве случаев производится также на эмуляторах.

## Рекомендации

Приложение при запуске и во время работы должно проверять косвенные и непосредственные значения параметров ОС, указывающие на наличие прав root и эмулятора.

**Определение эмулятора:**

* **Поиск файлов, характерных для различных эмуляторов:** `"ueventd.android_x86.rc"`, `"x86.prop"`, `"ueventd.ttVM_x86.rc"`, `"init.ttVM_x86.rc"`, `"fstab.ttVM_x86"`, `"fstab.vbox86"`, `"init.vbox86.rc"`, `"ueventd.vbox86.rc"`, `"/dev/socket/qemud"`, `"qemud"`, `"/dev/qemu_pipe"`, `"qemu_pipe"`, `"/system/lib/libc_malloc_debug_qemu.so"`, `"libc_malloc_debug_qemu.so"`, `"/sys/qemu_trace"`, `"/system/bin/qemu-props"`, `"qemu_trace"`, `"qemu-props"`, `"/dev/socket/genyd"`, `"genyd"`, `"/dev/socket/baseband_genyd"`, `"baseband_genyd"`, `"/proc/tty/drivers"`, `"drivers"`, `"/proc/cpuinfo"`, `"cpuinfo"`, `"/dev/goldfish_pipe"`, `"goldfish_pipe"`.

* **Проверка системных свойств:** `"init.svc.qemud"`, `"init.svc.qemu-props"`, `"qemu.hw.mainkeys"`, `"qemu.sf.fake_camera"`, `"qemu.sf.lcd_density"`, `"ro.bootloader"`, `"ro.bootmode"`, `"ro.hardware"`, `"ro.kernel.android.qemud"`, `"ro.kernel.qemu.gles"`, `"ro.kernel.qemu"`, `"ro.product.device"`, `"ro.product.model"`, `"ro.product.name"`, `"ro.serialno"`, `"ro.build.display.id"`, `"ro.product.cpu.abi"`, `"ro.debuggable"`, `"ro.secure"`.

* **Проверка полей класса Build:** `"FINGERPRINT"`, `"MODEL"`, `"MANUFACTURER"`, `"BRAND"`, `"BOARD"`, `"ID"`, `"SERIAL"`, `"TAGS"`, `"USER"`, `"HARDWARE"`,`"PRODUCT"`, `"TYPE"`.

    **Пример кода:**

        public static boolean isEmulator() {
            return (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")
                    || Build.FINGERPRINT.startsWith("generic")
                    || Build.FINGERPRINT.startsWith("unknown")
                    || Build.HARDWARE.contains("goldfish")
                    || Build.HARDWARE.contains("ranchu")
                    || Build.MODEL.contains("google_sdk")
                    || Build.MODEL.contains("Emulator")
                    || Build.MODEL.contains("Android SDK built for x86")
                    || Build.MANUFACTURER.contains("Genymotion")
                    || Build.PRODUCT.contains("sdk_google")
                    || Build.PRODUCT.contains("google_sdk")
                    || Build.PRODUCT.contains("sdk")
                    || Build.PRODUCT.contains("sdk_x86")
                    || Build.PRODUCT.contains("vbox86p")
                    || Build.PRODUCT.contains("emulator")
                    || Build.PRODUCT.contains("simulator"));
        }

* **Проверка телефонии: телефонный номер в списке известных фейковых номеров, device_id в списке известных фейковых device_id и т. п.**

    **Пример кода:**

        static final String[] DEVICE_IDS = {
                "000000000000000",
                "e21833235b6eef10",
                "012345678912345"
            };
            boolean checkDeviceId() {
                TelephonyManager telephonyManager =
                    (TelephonyManager) mContext.getSystemService(Context.TELEPHONY_SERVICE);

                @SuppressLint("HardwareIds") String deviceId = telephonyManager.getDeviceId();
                for (String known_deviceId : DEVICE_IDS) {
                    if (known_deviceId.equalsIgnoreCase(deviceId)) {
                        return true;
                    }
                }
                return false;
            } 

## Ссылки

1. [GitHub - framgia/android-emulator-detector: Easy to detect android emulator](https://github.com/framgia/android-emulator-detector) 

2. [Android Emulator Detection](https://ray-chong.medium.com/android-emulator-detection-4d0f994aab5e) 

3. [Emulator detection in Android](https://danielllewellyn.medium.com/emulator-detection-in-android-350efba44048) 

4. [Android Emulator Detection | VerSprite](https://versprite.com/blog/application-security/android-emulator-detection/) 

5. [owasp-mstg/0x05b-Basic-Security_Testing.md at master · OWASP/owasp-mstg](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05b-Basic-Security_Testing.md) 

6. [owasp-mstg/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md at master · OWASP/owasp-mstg](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md) 