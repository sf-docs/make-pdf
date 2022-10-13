# Обновление системы

## Обновление при наличии доступа к внешнему репозиторию docker-образов YCR

1. Остановите Stingray согласно инструкциям в разделе «[Остановка Stingray](./ostanovka_stingray.md)». 
2. Обновите специальный docker-образ для подготовки конфигурационных файлов командой:

        docker pull cr.yandex/crp8idtsajke3lbauqel/stingray/wizard:release-x

    !!! note "Примечание"
        Версия релиза указывается в формате `release-x`, где `x` — это текущая версия (например, 2022.6.1). Пожалуйста, уточняйте эту информацию у вендора или на официальном сайте.

3. Запустите docker-контейнер с параметром `update`.

        docker run -i -t -v /opt/stingray:/opt/docker-files cr.yandex/crp8idtsajke3lbauqel/stingray/wizard:release-x update

    !!! note "Примечание"
        Версия релиза указывается в формате `release-x`, где `x` — это текущая версия (например, 2022.6.1). Пожалуйста, уточняйте эту информацию у вендора или на официальном сайте.

4. После завершения копирования новых конфигурационных файлов необходимо выполнить команду обновления образов из директории с конфигурационными файлами (в примере `/opt/stingray`):

        docker-compose pull
        docker pull cr.yandex/crp8idtsajke3lbauqel/stingray/android_api27:release-x
        docker pull cr.yandex/crp8idtsajke3lbauqel/stingray/android_api30:release-x
        docker pull cr.yandex/crp8idtsajke3lbauqel/stingray/ios:release-x
        docker-compose up -d
        docker exec stingray-maintenance django-admin maintenance engines recreate

    !!! note "Примечание"
        Команда `recreate` пересоздает контейнеры в их ранее сохраненном состоянии, используя новые версии образов.

    !!! note "Примечание"
        Версия релиза указывается в формате `release-x`, где `x` — это текущая версия (например, 2022.6.1). Пожалуйста, уточняйте эту информацию у вендора или на официальном сайте.

    !!! note "Примечание"
        При скачивании нового образа старый образ не удаляется. Чтобы накопившиеся старые образы не занимали много места, рекомендуется их удалять, например, с помощью следующих команд:

            docker image prune

        Эта команда удалит все docker образы без тегов (у которых тег `<none>`). Следует учитывать, что она не удалит образы с предыдущими версиями. Например, если была установлена версия Stingray 2.7, а вместо нее поставили новую версию 2022.X, то старые образы не будут удалены, так как тег у старого образа будет 2.7, а не `<none>`.

            docker image prune -a

        Эта команда удалит docker образы без тегов (у которых тег <none>) и docker образы, которые не используются ни одним контейнером. Но в случае, если, например, ещё ни один engine контейнер для какого-нибудь нового образа не создавался (а такое может быть, например, если версия для iOS ещё не использовалась), то эта команда удалит соответствующий образ. Далее, когда возникнет необходимость создать контейнер из этого образа, то это сделать уже не удастся, так как такого образа уже не будет.

            docker image rm image_id

        Эта команда предназначена для индивидуального удаления образов.

5. В случае возникновения ошибок возможна загрузка образов вручную:

        docker pull cr.yandex/crp8idtsajke3lbauqel/stingray/stingray:release-x
        docker pull cr.yandex/crp8idtsajke3lbauqel/stingray/android_api27:release-x
        docker pull cr.yandex/crp8idtsajke3lbauqel/stingray/android_api30:release-x
        docker pull cr.yandex/crp8idtsajke3lbauqel/stingray/ios:release-x
        docker pull cr.yandex/crp8idtsajke3lbauqel/stingray/stingray-ui:release-x
        docker pull cr.yandex/crp8idtsajke3lbauqel/stingray/stingray-knowledgebase:release-x

    !!! note "Примечание"
        Версия релиза указывается в формате `release-x`, где `x` — это текущая версия (например, 2022.6.1). Пожалуйста, уточняйте эту информацию у вендора или на официальном сайте.

    После загрузки образов запустите систему согласно инструкциям в предыдущем пункте данного раздела.

6. Если осуществляется переход с версии Stingray 2.х на версию Stingray 2022.X, для корректной работы вновь установленной версии необходимо однократное выполнение команды:

        docker exec stingray-maintenance django-admin maintenance engines fill_id

    Эта команда обеспечивает корректное взаимодействие всех компонентов системы после обновления версии. Повторное выполнение этой команды не имеет смысла, но при этом Stingray продолжит корректно функционировать.

## Обновление при отсутствии доступа к внешнему репозиторию docker-образов YCR

1. Остановите Stingray согласно инструкциям в разделе «[Остановка Stingray](./ostanovka_stingray.md)».

2. При отсутствии доступа к внешнему репозиторию docker-образов, образы поставляются в виде выгруженных tar-архивов. Для доступа к данным архивам необходимо запросить их у поставщика продукта.

3. После того, как архивы загружены и перенесены на сервер Stingray необходимо их импортировать в docker. Для этого выполните следующую команду для всех полученных архивов:

        docker load -i <archive_name>.tar

4. Запустите специальный конфигуратор (Wizard) с параметром `update`.

        docker run -i -t -v /opt/stingray-docker-compose:/opt/docker-files cr.yandex/crp8idtsajke3lbauqel/stingray/wizard:release-x update

    !!! note "Примечание"
        Версия релиза указывается в формате `release-x`, где `x` — это текущая версия (например, 2022.6.1). Пожалуйста, уточняйте эту информацию у вендора или на официальном сайте.

5. После загрузки образов запустите систему согласно инструкциям в разделе в пунктах 4 и 6 раздела «[Обновление при наличии доступа к внешнему репозиторию docker-образов YCR](../obnovlenie_sistemy/#docker-gcp)».