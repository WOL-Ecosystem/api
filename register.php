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
        (isset($_POST["repeat_password"]) && !empty($_POST["repeat_password"]))) {

        //Password must include at least one uppercase and one lowercase characters, one number and one special charachter
        $passwordPattern = "/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^\w\s]).{8,32}$/";

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

        //Chech if the initialization of email, password and repeat_password comply.
        if (isset($email) && isset($password) && isset($repeat_password)) {

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
                if (checkAccountAvailability ($email)) {

                    //Save email and hashed password.
                    $credentials = array("email" => $email,
                                        "passwordHash" => hashPassword($password));

                    //Export the credentials as json.
                    file_put_contents($_SERVER['DOCUMENT_ROOT'] .
                        "/wols/userdata/$email.json", json_encode($credentials, JSON_PRETTY_PRINT));

                    //Raise the appropriate flags.
                    $ServerResponse = "SUCCESS";
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
        echo $ServerResponse;
    }
    //Handle missing post variables.
    else {
        if (!isset($_POST["email"]) || !isset($_POST["password"]) || !isset($_POST["repeat_password"])) {
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
    $input = stripslashes($input);
    $input = htmlspecialchars($input);
    return $input;
}
//Generate password hash.
function hashPassword ($password) {
    $options = [
        'cost' => 11,
    ];
    $passwordHash = password_hash($password, PASSWORD_BCRYPT, $options);
    return $passwordHash;
}
//Check if account exists or not.
function checkAccountAvailability ($email) {
    if (file_exists($_SERVER['DOCUMENT_ROOT'] . "/wols/userdata/". $email .".json")) {
        return false;
    }
    return true;
}
?>
