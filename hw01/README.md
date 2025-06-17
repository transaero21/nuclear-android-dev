# Домашнее Задание №1

## Условие

1. Научиться подключаться к телефону по ADB

2. Проверить версию ядра и uptime  
   `adb shell cat /proc/version`  
   `adb shell cat /proc/uptime`

3. Посмотреть список примонтированных разделов  
   `adb shell mount`

4. Увидеть нагрузку и процессы  
   `adb shell top`

5. Попробовать работу с файлами  
   `adb shell`  
   `cd /sdcard`  
   `mkdir testfolder`  
   `echo "Hello from ADB" > testfolder/testfile.txt`  
   `ls -l testfolder`  
   `cat testfolder/testfile.txt`

6. Сведения об установленных приложениях  
   `adb shell`  
   `pm list packages`  
   `pm list packages -3 # Найти отличия`  
   `dumpsys package com.android.chrome`

7. Снять лог  
   `adb logcat -v time # Остановка нажатием Ctrl + C`

8. Применить фильтр по тэгу и уровню  
   `adb logcat ActivityManager:I *:S`

9.  Просмотреть логи разных буферов  
   `logcat -b main`  
   `logcat -b system`  
   `logcat -b crash`  
   `logcat -b events`

10. Просмотреть системные свойства  
   `getprop ro.build.version.release`  
   `getprop ro.product.model`  
   `getprop ro.product.model`

11. Управление приложениями  
   `adb install путь_к_apk`  
   `adb uninstall <имя_пакета>`

12. Остановка и запуск приложений  
   `adb shell am force-stop <имя_пакета>`  
   `*adb shell am start -n <имя_пакета>/<имя_Activity>`  
   `-> adb shell am start -n com.android.settings/.Settings`

13. Снимки экрана и запись экрана  
   `adb shell screencap -p /sdcard/screen.png`  
   `adb pull /sdcard/screen.png`  
   `adb shell screenrecord /sdcard/demo.mp4`

14. Выполнить Monkey-тест  
   `monkey -p com.android.settings -v 10 # (!!! Аккуратно)`
