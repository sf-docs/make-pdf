# Перезапись файлов при использовании публичных архивов

<table class='noborder'>
    <colgroup>
      <col/>
      <col/>
    </colgroup>
    <tbody>
      <tr>
        <td rowspan="2"><img src="../../../img/defekt_vysokij.png"/></td>
        <td>Критичность:<strong> ВЫСОКИЙ</strong></td>
      </tr>
      <tr>
        <td>Способ обнаружения:<strong> IAST</strong></td>
      </tr>
    </tbody>
</table>

## Описание

При работе с архивами внутри приложения следует всегда проверять получаемые пути, чтобы избежать [path traversal](https://owasp.org/www-community/attacks/Path_Traversal) атаки.

Например, приложение открывает публично доступный архив и сохраняет данные из него в директорию `files/` приватной директории приложения. При этом в директории `shared_prefs/` находится файл настроек ***prefs.xml***. Злоумышленник или вредоносное приложение может изменить архив так, чтобы он включал файл с путем, содержащим символы "`..`", например так: `../shared_prefs/prefs.xml`. Тогда при распаковке архива файл ***prefs.xml*** попадет в директорию `shared_prefs/` приложения и перезапишет уже существующий там легальный файл ***prefs.xml***.

Таким же образом злоумышленник может перезаписать любые другие файлы, доступные приложению на запись, включая файлы баз данных, бинарные `*.so` файлы и файлы `*.dex`.

Чтобы избежать данной атаки, следует с осторожностью относиться к любым распаковываемым архивам и производить валидацию получаемых из них файловых путей.

``` java linenums="1" hl_lines="6" title="Пример уязвимого кода:"
ZipInputStream zin = new ZipInputStream(new FileInputStream(zipFile));
try {
    ZipEntry ze = null;

    while ((ze = zin.getNextEntry()) != null) {
        String path = location + ze.getName();

        if (ze.isDirectory()) {
            File unzipFile = new File(path);
            if(!unzipFile.isDirectory()) {
                unzipFile.mkdirs();
            }
        }
        else { 
            FileOutputStream fout = new FileOutputStream(path, false);
            try {
                for (int c = zin.read(); c != -1; c = zin.read()) {
                    fout.write(c);
                }
                zin.closeEntry();
            }
            finally {
                fout.close();
            }
        }
    }
}
finally {
    zin.close();
}
```

Приведенный выше код достаточно популярен — проблема в том, что в строке 6, где происходит создание файлового пути для новой сущности, не производится валидация значения пришедшего из метода `getName()`.

## Рекомендации

Для предотвращения таких уязвимостей необходимо придерживаться следующих правил:

1.	Санитизация путей, содержащих "`..`" и отказ от их использования в приложении.
2.	Использование проверки на канонический путь:

    ``` java linenums="1" title="Пример:"
    File unzipFile = new File(path);
    Log.d("file", unzipFile.getCanonicalPath());
    Log.d("file", unzipFile.getAbsolutePath());
    Log.d("file", unzipFile.getPath());
    ```

    Данный код выведет:

        /data/data/package_id/shared_prefs/prefs.xml
        /data/user/0/package_id/files/../shared_prefs/prefs.xml
        /data/user/0/package_id/files/../shared_prefs/prefs.xml

    Очевидно, что для проверок надо использовать путь в каноническом представлении!

3. Приложение может использовать файловые пути, получаемые из архива специфическим образом, в каждом конкретном случае следует учитывать возможность наличия вредоносных путей в открываемом архиве и принимать соответствующие меры.

## Ссылки

1. [https://owasp.org/www-community/attacks/Path_Traversal](https://owasp.org/www-community/attacks/Path_Traversal) 
2. [https://portswigger.net/web-security/file-path-traversal](https://portswigger.net/web-security/file-path-traversal) 
3. [https://en.wikipedia.org/wiki/Directory_traversal_attack](https://en.wikipedia.org/wiki/Directory_traversal_attack) 
