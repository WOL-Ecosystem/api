<?php
//Display errors if any
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

//Check if client connection is of type POST
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    //Check if POST data exists as variables and are not empty
    if ((isset($_POST["email"]) && !empty($_POST["email"])) &&
        (isset($_POST["password"]) && !empty($_POST["password"])) &&
        (isset($_POST["repeat_password"]) && !empty($_POST["repeat_password"])) &&
        (isset($_POST["mac_address"]) && !empty($_POST["mac_address"]))) {

        //Password must include at least one uppercase and one lowercase characters, one number and one special charachter
        $passwordPattern = "/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^\w\s]).{9,32}$/";
        $mac_addressPattern = "/^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$/";

        /*
        Check email and if is valid, save it and raise the respective flag.
        If email is invalid dont save it and raise respective flag.
        */
        if (filter_var($_POST["email"], FILTER_VALIDATE_EMAIL)) {
            $email = checkInput($_POST["email"]);
        }
        else {
            die("INVALID_EMAIL");
        }

        /*
        Check password and if is valid, save it and raise the respective flag.
        If password is invalid dont save it and raise respective flag.
        */
        if (preg_match($passwordPattern, $_POST["password"])) {
            $password = checkInput($_POST["password"]);
        }
        else {
            die("INVALID_PASSWORD");
        }

        /*
        Check repeat_password and if is valid, save it and raise the respective flag.
        If repeat_password is invalid dont save it and raise respective flag.
        */
        if (preg_match($passwordPattern, $_POST["repeat_password"])) {
            $repeat_password = checkInput($_POST["repeat_password"]);
        }
        else {
            die("INVALID_REPEAT_PASSWORD");
        }

        /*
        Check mac_address and if is valid, save it and raise the respective flag.
        If mac_address is invalid dont save it and raise respective flag.
        */
        if (preg_match($mac_addressPattern, $_POST["mac_address"])) {
            $mac_address = checkMac($_POST["mac_address"]);
        }
        else {
            die("INVALID_MAC_ADDRESS");
        }

        //Chech if the initialization of email, password and repeat_password comply.
        if (isset($email) && isset($password) && isset($repeat_password) && isset($mac_address)) {

            //Chech if password and repeat_password match.
            if (strcmp($password, $repeat_password) == 0) {

                /*
                Check if the required directory exists.
                If does not exist, create it.
                */
                if (!file_exists($_SERVER['DOCUMENT_ROOT'] . "/wols/userdata/")) {
                    mkdir($_SERVER['DOCUMENT_ROOT'] . "/wols/userdata/");
                }

                //Check if account exists. If does not, create it.
                if (checkAccountAvailability($email)) {
                    //Set default time zone
                    date_default_timezone_set('Europe/Athens');
                    $passwordHash = hashInput($password);
                    $passwordDoubleHash = hashInput($passwordHash);
                    //Save email, hashed password and date of creation.
                    $credentials = array("email" => $email,
                                        "passwordHash" => $passwordHash,
                                        "passwordDoubleHash" => $passwordDoubleHash,
                                        "macAddress" => $mac_address,
                                        "dateCreated" => date_format(date_create(), 'Y-m-d H:i:s'));

                    //Export the credentials as json.
                    file_put_contents($_SERVER['DOCUMENT_ROOT'] .
                        "/wols/userdata/$email.json", json_encode($credentials, JSON_PRETTY_PRINT));


                    //Respond to client.
                    $ServerResponse = array("Response" => "SUCCESS",
                                        "Token" => $passwordDoubleHash);

                }
                //Account exixts. Exit with appropriate message.
                else {
                    die("ACCOUNT_ALREADY_EXISTS");
                }

            }
            /*Password and repeat_password dont match. Exit with appropriate message.
            */
            else {
                die("PASSWORDS_DONT_MATCH");
            }
        }

        //Server response
        //echo $ServerResponse;
        echo json_encode($ServerResponse);
    }
    //Handle missing post variables.
    else {
        if (!isset($_POST["email"]) || !isset($_POST["password"]) ||
            !isset($_POST["repeat_password"]) || !isset($_POST["mac_address"])) {
            die("FORM_DATA_MISSING");
        }
        else {
            die("FORM_DATA_EMPTY");
        }
    }
}
//Handle error if connection is not of type POST.
else {
    die("POST_REQUIRED");
}

//Comply the input with only accepted characters.
function checkInput ($input) {
    $input = trim($input);
    $input = htmlspecialchars($input);
    return $input;
}

function checkMac ($input) {
    $input = strtoupper($input);
    return $input;
}

//Generate password hash.
function hashInput ($input) {
    $options = [
    'memory_cost' => 2048,
    'time_cost' => 4,
    'threads' =>3
    ];
    $inputHash = password_hash($input, PASSWORD_ARGON2I, $options);
    return $inputHash;
}

//Check if account exists or not.
function checkAccountAvailability ($email) {
    if (file_exists($_SERVER['DOCUMENT_ROOT'] . "/wols/userdata/". $email .".json")) {
        return false;
    }
    return true;
}
?>
