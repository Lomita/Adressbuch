<?php
    require 'dataBaseConnection.php';
    session_start();
?>

<!doctype html>
<html lang="en">
    <head>
        <!-- Required meta tags -->
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

        <!-- Bootstrap CSS -->
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css" integrity="sha384-MCw98/SFnGE8fJT3GXwEOngsV7Zt27NXFoaoApmYm81iuXoPkFOJwJ8ERdknLPMO" crossorigin="anonymous">
        <title>Adressbuch Pro | Home</title>
        </head>
    <body>
        <div class="container">  
            <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
                <a class="navbar-brand align-middle" href="adressbuch.php">
                <img src="../img/nav-bar-icon.svg" width="35" height="35" class="d-inline-block align-middle" alt=""> Adressbuch Pro</a>
                <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
                    <span class="navbar-toggler-icon"></span>
                </button>
                <div class="collapse navbar-collapse" id="navbarSupportedContent">
                    <ul class="navbar-nav mr-auto ">
                        <?php
                            //handle navigation items for user and guests
                            if(isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true)
                                echo '<li class="nav-item dropdown">
                                <a class="nav-link dropdown-toggle" data-toggle="dropdown" href="#" role="button" aria-haspopup="true" aria-expanded="false">Account<span class="sr-only">(current)</span></a>
                                <div class="dropdown-menu" aria-labelledby="navbarDropdown">
                                    <a class="dropdown-item" href="user_info.php">Account Übersicht</a>
                                    <a class="dropdown-item" href="logout.php">Abmelden</a>
                                </div>
                                </li>
                                <li class="nav-item active ">
                                    <a class="nav-link align-middle" >Angemeldet als '.$_SESSION['username'].' <span class="sr-only">(current)</span></a>
                                </li>';
                            else
                                echo '<li class="nav-item active">
                                        <a class="nav-link" align="right" href="login.php">Anmelden <span class="sr-only">(current)</span></a>
                                    </li>
                                    <li class="nav-item active">
                                        <a class="nav-link" href="register.php">Registrieren <span class="sr-only">(current)</span></a>
                                    </li>';
                        ?>
                    </ul>    
                </div>
            </nav>
            </div>
            <br>
            <br>
            <div class="container">
                <?php
                    //add contact
                    if(isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true)
                    {
                        echo '<form method="post" action="">
                        <div class="input-group mb-3">
                            <input type="text" class="form-control" name="search_text" placeholder="Kontaktinformation" aria-label="Kontaktinformation" aria-describedby="button-addon2">
                            <div class="input-group-append">
                                <input type="submit" class="btn btn-dark" name="Suchen" value="Suchen" id="button-addon2"></button>
                            </div>
                            </div>
                            </form>';
                          echo '<div class="btn-toolbar float-right" role="toolbar">
                                    <div class="btn-group mr-2" role="group">
                                        <button type="button" class="btn btn-success text-white font-weight-bold" data-toggle="modal" data-target="#addContactModal">+</button>
                                    </div>
                                    <div class="btn-group mr-2" role="group">
                                        <button type="button" class="btn btn-warning text-white font-weight-bold" data-toggle="modal" data-target="#modifyContactModal">&</button>
                                    </div>
                                    <div class="btn-group mr-2" role="group">
                                        <button type="button" class="btn btn-danger  text-white font-weight-bold" data-toggle="modal" data-target="#delContactModal">--</button>
                                    </div></div>';      
                          
                            //add modal
                          echo '<div class="modal fade" id="addContactModal" tabindex="-1" role="dialog" aria-labelledby="myModalLabel">
                          <div class="modal-dialog" role="document">
                            <div class="modal-content">
                              <div class="modal-header">
                                <h4 class="modal-title" id="myModalLabel">Kontakt Hinzufügen</h4>
                                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">×</span></button> 
                              </div>
                              
                              <div class="modal-body">
                                    <form method="post" action="add_contact.php">
                                        <div class="form-group ">
                                        <label class="control-label requiredField" for="firstname">
                                        Vorname
                                        <span class="asteriskField">
                                            *
                                        </span>
                                        </label>
                                        <input class="form-control" id="firstname" name="firstname" type="text" maxlength="30" required/>
                                        </div>
                                        <div class="form-group ">
                                        <label class="control-label requiredField" for="lastname">
                                        Nachname
                                        <span class="asteriskField">
                                            *
                                        </span>
                                        </label>
                                        <input class="form-control" id="lastname" name="lastname" type="text" maxlength="30" required/>
                                        </div>
                                        <div class="form-group ">
                                        <label class="control-label requiredField" for="email">
                                        Email
                                        <span class="asteriskField">
                                            *
                                        </span>
                                        </label>
                                        <input class="form-control" id="email" name="email" placeholder="example@exp.com" type="email" required/>
                                        </div>
                                        <div class="form-group ">
                                        <label class="control-label requiredField" for="description">
                                        Beschreibung
                                        <span class="asteriskField">
                                            *
                                        </span>
                                        </label>
                                        <textarea class="form-control" cols="40" id="description" maxlength="1000" name="description" placeholder="Kontakt Beschreibung" rows="3" required></textarea>
                                        </div>
                                        <div class="form-group ">
                                        <label class="control-label requiredField" for="phone">
                                        Tel.
                                        <span class="asteriskField">
                                            *
                                        </span>
                                        </label>
                                        <input type="text" pattern="[0-9]{3} [0-9]{3} [0-9]{2} [0-9]{2}" class="form-control" id="phone" name="phone" placeholder="070 123 45 67" required/>
                                        </div>
                                        <div class="form-group ">
                                        <label class="control-label requiredField" for="place">
                                        Ort
                                        <span class="asteriskField">
                                            *
                                        </span>
                                        </label>
                                        <input class="form-control" id="place" maxlength="100" name="place" type="text" required/>
                                        </div>
                                        <div class="form-group ">
                                        <label class="control-label requiredField" for="plz">
                                        PLZ
                                        <span class="asteriskField">
                                            *
                                        </span>
                                        </label>
                                        <input class="form-control" id="plz" name="plz" pattern="[0-9]{4}" type="text" required/>
                                        </div>
                                        <div class="form-group ">
                                        <label class="control-label requiredField" for="date">
                                        Datum
                                        <span class="asteriskField">
                                            *
                                        </span>
                                        </label>
                                        <input class="form-control" id="date" name="date" type="date" required/>
                                        </div>
                                        <div class="form-group">
                                            <div class="float-right">
                                                <button type="button" class="btn btn-default" data-dismiss="modal">
                                                    Schließen
                                                </button>
                                                <button class="btn btn-success" type="submit">
                                                    Hinzufügen
                                                </button>
                                            </div>
                                        </div>
                                        </form>
                                    </div>
                            </div>
                          </div>
                        </div>';

                        //modify modal
                        echo '<div class="modal fade" id="modifyContactModal" tabindex="-1" role="dialog" aria-labelledby="myModalLabel">
                        <div class="modal-dialog" role="document">
                          <div class="modal-content">
                            <div class="modal-header">
                              <h4 class="modal-title" id="myModalLabel">Kontakt Bearbeiten</h4>
                              <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">×</span></button> 
                            </div>
                            
                            <div class="modal-body">
                                  <form method="post" action="modify_contact.php">
                                      <div class="form-group ">
                                      <label class="control-label requiredField" for="contact_id">
                                      Kontakt ID
                                      <span class="asteriskField">
                                        *
                                      </span>
                                      </label>
                                      <input class="form-control" id="contact_id" name="contact_id" type="number" maxlength="6" required/>
                                      </div>
                                      <div class="form-group ">
                                      <label class="control-label requiredField" for="firstname">
                                      Vorname
                                      <span class="asteriskField">
                                        *
                                      </span>
                                      </label>
                                      <input class="form-control" id="firstname" name="firstname" type="text" maxlength="30" required/>
                                      </div>
                                      <div class="form-group ">
                                      <label class="control-label requiredField" for="lastname">
                                      Nachname
                                      <span class="asteriskField">
                                        *
                                      </span>
                                      </label>
                                      <input class="form-control" id="lastname" name="lastname" type="text" maxlength="30" required/>
                                      </div>
                                      <div class="form-group ">
                                      <label class="control-label requiredField" for="email">
                                      Email
                                      <span class="asteriskField">
                                        *
                                      </span>
                                      </label>
                                      <input class="form-control" id="email" name="email" placeholder="example@exp.com" type="email" required/>
                                      </div>
                                      <div class="form-group ">
                                      <label class="control-label requiredField" for="description">
                                      Beschreibung
                                      <span class="asteriskField">
                                        *
                                      </span>
                                      </label>
                                      <textarea class="form-control" cols="40" id="description" maxlength="1000" name="description" placeholder="Kontakt Beschreibung" rows="3" required></textarea>
                                      </div>
                                      <div class="form-group ">
                                      <label class="control-label requiredField" for="phone">
                                      Tel.
                                      </label>
                                      <input type="text" pattern="[0-9]{3} [0-9]{3} [0-9]{2} [0-9]{2}" class="form-control" id="phone" name="phone" placeholder="070 123 45 67" required/>
                                      </div>
                                      <div class="form-group ">
                                      <label class="control-label requiredField" for="place">
                                      Ort
                                      <span class="asteriskField">
                                        *
                                      </span>
                                      </label>
                                      <input class="form-control" id="place" maxlength="100" name="place" type="text" required/>
                                      </div>
                                      <div class="form-group ">
                                      <label class="control-label requiredField" for="plz">
                                      PLZ
                                      <span class="asteriskField">
                                        *
                                      </span>
                                      </label>
                                      <input class="form-control" id="plz" name="plz" pattern="[0-9]{4}" type="text" required/>
                                      </div>
                                      <div class="form-group ">
                                      <label class="control-label requiredField" for="date">
                                      Datum
                                      <span class="asteriskField">
                                        *
                                      </span>
                                      </label>
                                      <input class="form-control" id="date" name="date" type="date" required/>
                                      </div>
                                      <div class="form-group">
                                          <div class="float-right">
                                              <button type="button" class="btn btn-default" data-dismiss="modal">
                                                  Schließen
                                              </button>
                                              <button class="btn btn-warning" type="submit">
                                                  Ändern
                                              </button>
                                          </div>
                                      </div>
                                      </form>
                                  </div>
                          </div>
                        </div>
                      </div>';

                        //del modal
                        echo '<div class="modal fade" id="delContactModal" tabindex="-1" role="dialog" aria-labelledby="myModalLabel">
                        <div class="modal-dialog" role="document">
                          <div class="modal-content">
                            <div class="modal-header">
                              <h4 class="modal-title" id="myModalLabel">Kontakt Löschen</h4>
                              <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">×</span></button> 
                            </div>
                            
                            <div class="modal-body">
                                  <form method="post" action="del_contact.php">
                                      <div class="form-group ">
                                      <label class="control-label requiredField" for="contact_id">
                                      Kontakt ID
                                      <span class="asteriskField">
                                          *
                                      </span>
                                      </label>
                                      <input class="form-control" id="contact_id" name="contact_id" type="number" maxlength="6" required/>
                                      </div>
                                      <div class="form-group">
                                          <div class="float-right">
                                              <button type="button" class="btn btn-default" data-dismiss="modal">
                                                  Schließen
                                              </button>
                                              <button class="btn btn-danger" type="submit">
                                                  Löschen
                                              </button>
                                          </div>
                                      </div>
                                      </form>
                                  </div>
                          </div>
                        </div>
                      </div>';
                    }
                ?>
                <br>
                <br>
                <br>
                <?php
                    //search contact             
                    if(isset($_POST['search_text']))
                    {
                        $search_text = htmlspecialchars(trim($_POST['search_text']));
                        if(isset($search_text) && $search_text === "")
                            exit;
                        $query = "SELECT * FROM contacts";
		                $stmt = $mysqli->prepare($query);
		                $stmt->execute();
                        $result = $stmt->get_result();
                        
                        echo '<table class="table"><thead class="text-white bg-dark">
                                            <tr>
                                                <th scope="col">ID</th>
                                                <th scope="col">Vorname</th>
                                                <th scope="col">Nachname</th>
                                                <th scope="col">E-Mail</th>
                                                <th scope="col">Beschreibung</th>
                                                <th scope="col">Tel.</th>
                                                <th scope="col">Ort</th>
                                                <th scope="col">PLZ</th>
                                                <th scope="col">Datum</th>
                                            </tr>
                                          </thead><tbody>';
                        if(isset($search_text) && stristr("*", $search_text))
                        {
                            while($contact = $result->fetch_assoc())
                            {
                                echo '<tr>';
                                foreach($contact as $contact_info)
                                    echo '<td>'. $contact_info . '</td>';
                                echo '</tr>';
                            }
                        }
                        else
                        {
                            $match = false;
                            while($contact = $result->fetch_assoc())
                            {
                                foreach($contact as $contact_info)
                                {
                                    if(stristr(trim($contact_info), $search_text))
                                    {
                                        echo '<tr>';
                                        foreach($contact as $contact_info)
                                            echo '<td>'. $contact_info . '</td>';
                                        echo '</tr>';
                                        $match = true;
                                        break;
                                    }                                
                                }
                            }
                            if($match === false)
                                echo '<td>'.$search_text.' konnte nicht gefunden werden!</td>';
                        }

                        echo '</tbody></table>';
                        if(isset($_POST['search_text']))
                            $_POST['search_text'] = ""; 
                    }
                ?>
            </div>
        <!-- Optional JavaScript -->
        <!-- jQuery first, then Popper.js, then Bootstrap JS -->
        <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.3/umd/popper.min.js" integrity="sha384-ZMP7rVo3mIykV+2+9J3UJ46jBk0WLaUAdn689aCwoqbBJiSnjAK/l8WvCWPIPm49" crossorigin="anonymous"></script>
        <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/js/bootstrap.min.js" integrity="sha384-ChfqqxuZUCnJSK3+MXmPNIyE6ZbWh2IMqE241rYiqJxyMiZ6OW/JmZQ5stwEULTy" crossorigin="anonymous"></script>
    </body>
</html>

