<?php
define('API_ACCESS_KEY',"AAAAtO89RoI:APA91bF_RzRK7jw3kfKFWCjsqwcpgGmcadZziSfAk6KC5ertG9TzQ8QrJM3HU63YNuNx-edjH59uHRfktqT4laq_k0kDdAAyz_xODrjtbJVjkzZpn9GxUhGsVaAoJPM0oplpNiaGHe_L");
 $fcmUrl = 'https://fcm.googleapis.com/fcm/send';
 $token='dE5W3wQrTheFPbNZo6ciFK:APA91bFxOmLbt_fAruZHzJLKiOXjA4uREXlrEfENdDo-pu4vEJhypMJWxNx1doYTMiB6QU2bnLOwVFh5dxmPjvmF-qPBh7W6undVh4MhQk4LrROcDs7kzddk_MS8j9dma5Djj6LHj4yO';

    $notification = [
            'title' =>'ALLY',
            'body' => 'hello you got a notification',
            'icon' =>'myIcon', 
            'sound' => 'mySound',
            'image' => 'http://res.cloudinary.com/riz0000000001/image/upload/v1626265739/lffkokrcxekzpl1xt357.jpg'
        ];
        echo $notification['title'];
        echo $notification['body'];
        echo $notification['icon'];
        echo $notification['sound'];

        $extraNotificationData = ["data" => $notification];
        $fcmNotification = [
            //'registration_ids' => $tokenList, //multple token array
            'to'        => $token, //single token
            'notification' => $notification,
            'data' => $extraNotificationData
        ];

        $headers = [
            'Authorization: key=' . API_ACCESS_KEY,
            'Content-Type: application/json'
        ];


        $ch = curl_init();
        echo $ch;
        echo "hey";
        curl_setopt($ch, CURLOPT_URL,$fcmUrl);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($fcmNotification));
        $result = curl_exec($ch);
        curl_close($ch);


        echo $result;
?>