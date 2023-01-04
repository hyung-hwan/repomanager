<section class="main">

    <h3>OVERVIEW</h3>

    <br>
        <div class="hosts-charts-container">
            <?php
            if ($totalHosts == 0) {
                echo '<p>No host configured yet.</p>';
            }

            if ($totalHosts >= 1) : ?>
                <div class="hosts-chart-sub-container div-generic-blue">
                    <span class="hosts-chart-title">Hosts (<?= $totalHosts ?>)</span>
                    <canvas id="hosts-count-chart" class="host-pie-chart"></canvas>
                </div>

                <?php
                if (!empty($kernelList)) : ?>
                    <div class="hosts-chart-sub-container div-generic-blue">
                        <span class="hosts-chart-title">Kernels</span>
                    
                        <div class="hosts-charts-list-column-container">
                            <?php
                            foreach ($kernelList as $kernel) :
                                if (empty($kernel['Kernel'])) {
                                    $kernelName = 'Unknow';
                                } else {
                                    $kernelName = $kernel['Kernel'];
                                } ?>
                                <div class="hosts-charts-list-container">
                                    <div class="hosts-charts-list-label" chart-type="kernel" kernel="<?= $kernelName ?>">
                                        <div>
                                            <!-- square figure -->
                                            <span style="background-color: <?= $mycolor->randomColor() ?>"></span>
                                            <span><?= $kernelName ?></span>
                                        </div>
                                        <span><?= $kernel['Kernel_count'] ?></span>
                                    </div>
                                    <div class="hosts-charts-list-data">
                                        <span></span>
                                    </div>
                                </div>
                                <?php
                            endforeach ?>
                        </div>
                    </div>
                    <?php
                endif;

                if (!empty($profilesList)) : ?>
                    <div class="hosts-chart-sub-container div-generic-blue">
                        <span class="hosts-chart-title">Profiles</span>
                        <div class="hosts-charts-list-column-container">
                            <?php
                            foreach ($profilesList as $profile) {
                                if (empty($profile['Profile'])) {
                                    $profileName = 'Unknow';
                                } else {
                                    $profileName = $profile['Profile'];
                                } ?>
                                
                                <div class="hosts-charts-list-container">
                                    <div class="hosts-charts-list-label" chart-type="profile" profile="<?= $profileName ?>">
                                        <div>
                                            <!-- square figure -->
                                            <span style="background-color: <?= $mycolor->randomColor() ?>"></span>
                                            <span><?= $profileName ?></span>
                                        </div>
                                        <span><?= $profile['Profile_count'] ?></span>
                                    </div>
                                    <div class="hosts-charts-list-data">
                                        <span></span>
                                    </div>
                                </div>
                                <?php
                            } ?>
                        </div>
                    </div>
                    <?php
                endif;

                if (!empty($osList)) : ?>
                    <div class="hosts-chart-sub-container div-generic-blue">
                        <span class="hosts-chart-title">Operating systems</span>
                        <canvas id="hosts-os-chart" class="host-bar-chart"></canvas>
                    </div>
                    <?php
                endif;

                if (!empty($archList)) : ?>
                    <div class="hosts-chart-sub-container div-generic-blue">
                        <span class="hosts-chart-title">Architectures</span>
                        <canvas id="hosts-arch-chart" class="host-pie-chart"></canvas>
                    </div>
                    <?php
                endif;

                if (!empty($envsList)) : ?>
                    <div class="hosts-chart-sub-container div-generic-blue">
                        <span class="hosts-chart-title">Environments</span>
                        <canvas id="hosts-env-chart" class="host-pie-chart"></canvas>
                    </div>
                    <?php
                endif;

                if (!empty($agentStatusList)) : ?>
                    <div class="hosts-chart-sub-container div-generic-blue">
                        <span class="hosts-chart-title">Agent status</span>
                        <canvas id="hosts-agent-status-chart" class="host-pie-chart"></canvas>
                    </div>
                    <?php
                endif;

                if (!empty($agentVersionList)) : ?>
                    <div class="hosts-chart-sub-container div-generic-blue">
                        <span class="hosts-chart-title">Agent release version</span>
                        <canvas id="hosts-agent-version-chart" class="host-pie-chart"></canvas>
                    </div>
                    <?php
                endif ?>

                <div class="div-generic-blue">
                    <span class="hosts-chart-title">No data yet</span>
                </div>
                <?php
            endif; ?>
        </div>

        <div id="hostsDivLoading">
            <p class="center">Loading data<img src="resources/images/loading.gif" class="icon" /></p>
        </div>

        <?php
        if ($totalHosts >= 1) : ?>
            <div id="hostsDiv" class="hide">
                <?php
                /**
                 *  Récupération des noms des groupes
                 */
                $groupsList = $group->listAllWithDefault(); ?>
                <div>
                    <div id="title-button-div">
                        <h3>HOSTS</h3>

                        <?php
                        if (IS_ADMIN) : ?>
                            <div id="title-button-container">
                                <div id="GroupsListToggleButton" class="slide-btn" title="Manage hosts groups">
                                    <img src="resources/icons/folder.svg" />
                                    <span>Manage groups</span>
                                </div>

                                <div id="settingsToggleButton" class="slide-btn" title="Edit display settings">
                                    <img src="resources/icons/cog.svg" />
                                    <span>Settings</span>
                                </div>
                            </div>
                            <?php
                        endif ?>
                    </div>

                    <?php
                    if (!empty($groupsList)) :
                        /**
                         *  Si il y a au moins 1 hôte actif alors on fait apparaitre les champs de recherche
                         */
                        if ($totalHosts != 0) : ?>
                            <div class="searchInput-container">
                                <div class="searchInput-subcontainer">
                                    <div>
                                        <p>
                                            <img src="resources/icons/info.svg" class="icon-lowopacity" title="You can specify a filter before your search entry:&#13;os:<os name> <search>&#13;os_version:<os version> <search>&#13;os_family:<os family> <search>&#13;type:<virtualization type> <search>&#13;kernel:<kernel> <search>&#13;arch:<architecture> <search>" />Search host:                                            
                                        </p>
                                        <input type="text" id="searchHostInput" onkeyup="searchHost()" class="input-large" autocomplete="off" placeholder="Hostname, IP" />
                                    </div>
                                    <div>
                                        <p>Search package:</p>
                                        <input type="text" id="searchHostPackageInput" onkeyup="searchHostPackage()" class="input-large" autocomplete="off" placeholder="Package name" />
                                    </div>
                                </div>
                            </div>
                            <?php
                        endif ?>
                        
                        <div class="groups-container">
                            <?php
                            foreach ($groupsList as $groupName) :
                                /**
                                 *  Récupération de la liste des hôtes du groupe
                                 */
                                $hostsList = $myhost->listByGroup($groupName);
                                /**
                                 *  Si il s'agit du groupe par défaut 'Default' et que celui-ci ne possède aucun hôte alors on ignore son affichage
                                 */
                                if ($groupName == "Default" and empty($hostsList)) {
                                    continue;
                                } ?>
                                <input type='hidden' name='groupname' value='<?=$groupName?>'>
                
                                <div class="div-generic-blue hosts-group-container">
                                    <?php
                                    /**
                                     *  On affiche le nom du groupe sauf si il s'agit du groupe Default
                                     */
                                    if ($groupName != "Default") :
                                        echo '<h3>';
                                        echo $groupName;
                                        /**
                                         *  Affichage du nombre d'hôtes dans ce groupe
                                         */
                                        if (!empty($hostsList)) {
                                            echo ' (' . count($hostsList) . ')';
                                        }
                                        echo '</h3>';
                                    endif;
                                    if (IS_ADMIN) :
                                        /**
                                         *  Boutons d'actions sur les checkbox sélectionnées
                                         */ ?>
                                        <div class="js-buttons-<?=$groupName?> hide">
                                            
                                            <h5>Request selected host(s) to send informations:</h5>
                                            <button class="hostsActionBtn pointer btn-fit-green" action="general-status-update" group="<?=$groupName?>" title="Send general informations (OS and state informations)."><img src="resources/icons/update.svg" class="icon" /><b>General informations</b></button>
                                            <button class="hostsActionBtn pointer btn-fit-green" action="packages-status-update" group="<?=$groupName?>" title="Send packages informations (available, installed, updated...)."><img src="resources/icons/update.svg" class="icon" /><b>Packages informations</b></button>
                                            <h5>Request selected host(s) to execute an action:</h5>
                                            <button class="hostsActionBtn pointer btn-fit-yellow" action="update" group="<?=$groupName?>" title="Update all available packages."><img src="resources/icons/update.svg" class="icon" /><b>Update packages</b></button>
                                            
                                            <h5>Delete or reset selected host(s):</h5>
                                            <button class="hostsActionBtn pointer btn-fit-red" action="reset" group="<?=$groupName?>" title="Reset known data."><img src="resources/icons/update.svg" class="icon" /><b>Reset</b></button>
                                            <button class="hostsActionBtn pointer btn-fit-red" action="delete" group="<?=$groupName?>" title="Delete."><img src="resources/icons/bin.svg" class="icon" /><b>Delete</b></button>
                                        </div>
                                        <?php
                                    endif;
                                    /**
                                     *  Affichage des hôtes du groupe
                                     */
                                    if (!empty($hostsList)) { ?>
                                        <table class="hosts-table">
                                            <thead>
                                                <tr>
                                                    <td></td>
                                                    <td></td>
                                                    <td></td>
                                                    <td></td>
                                                    <td title="Total installed packages."><span>Inst.</span></td>
                                                    <td title="Total available updates."><span>Avail.</span></td>
                                                    <td></td>
                                                    <?php
                                                    if (IS_ADMIN) : ?>
                                                        <td>
                                                            <span class="js-select-all-button pointer" group="<?=$groupName?>">Select all</span>
                                                        </td>
                                                        <?php
                                                    endif ?>
                                                    <td></td>
                                                    <td></td>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php
                                                /**
                                                 *  Traitement de la liste des hôtes
                                                 *  Ici on va afficher le détails de chaque hôte et on en profites pour récupérer certaines informations supplémentaires en base de données
                                                 */
                                                foreach ($hostsList as $host) {
                                                    $id = $host['Id'];
                                                    if (!empty($host['Hostname'])) {
                                                        $hostname = $host['Hostname'];
                                                    } else {
                                                        $hostname = 'unknow';
                                                    }
                                                    if (!empty($host['Ip'])) {
                                                        $ip = $host['Ip'];
                                                    } else {
                                                        $ip = 'unknow';
                                                    }
                                                    if (!empty($host['Os'])) {
                                                        $os = $host['Os'];
                                                    } else {
                                                        $os = 'unknow';
                                                    }
                                                    if (!empty($host['Os_version'])) {
                                                        $os_version = $host['Os_version'];
                                                    } else {
                                                        $os_version = 'unknow';
                                                    }
                                                    if (!empty($host['Os_family'])) {
                                                        $os_family = $host['Os_family'];
                                                    } else {
                                                        $os_family = 'unknow';
                                                    }
                                                    if (!empty($host['Type'])) {
                                                        $type = $host['Type'];
                                                    } else {
                                                        $type = 'unknow';
                                                    }
                                                    if (!empty($host['Kernel'])) {
                                                        $kernel = $host['Kernel'];
                                                    } else {
                                                        $kernel = 'unknow';
                                                    }
                                                    if (!empty($host['Arch'])) {
                                                        $arch = $host['Arch'];
                                                    } else {
                                                        $arch = 'unknow';
                                                    }
                                                    if (!empty($host['Profile'])) {
                                                        $profile = $host['Profile'];
                                                    } else {
                                                        $profile = 'unknow';
                                                    }
                                                    if (!empty($host['Env'])) {
                                                        $env = $host['Env'];
                                                    } else {
                                                        $env = 'unknow';
                                                    }
                                                    /**
                                                     *  On défini le status de l'agent
                                                     *  Ce status peut passer en 'stopped' si l'agent n'a pas donné de nouvelles après 1h
                                                     */
                                                    $agentStatus = $host['Online_status'];
                                                    /**
                                                     *  On vérifie que la dernière fois que l'agent a remonté son status est inférieur à 1h (et 10min de "marge")
                                                     */
                                                    if ($host['Online_status_date'] != DATE_YMD or $host['Online_status_time'] <= date('H:i:s', strtotime(date('H:i:s') . ' - 70 minutes'))) {
                                                        $agentStatus = 'seems-stopped';
                                                    }
                                                    /**
                                                     *  Message du dernier état connu
                                                     */
                                                    $agentLastSendStatusMsg = 'state on ' . DateTime::createFromFormat('Y-m-d', $host['Online_status_date'])->format('d-m-Y') . ' at ' . $host['Online_status_time'];
                                                    /**
                                                     *  On ouvre la BDD dédiée de l'hôte à partir de son ID pour pouvoir récupérer des informations supplémentaires.
                                                     */
                                                    $myhost->openHostDb($id);
                                                    /**
                                                     *  Récupération des paquets disponibles pour installation
                                                     */
                                                    $packagesAvailableTotal = count($myhost->getPackagesAvailable());
                                                    /**
                                                     *  Récupération du nombre total de paquets installés
                                                     */
                                                    $packagesInstalledTotal = count($myhost->getPackagesInstalled());
                                                    /**
                                                     *  Si le nombre total de paquets disponibles récupéré précédemment est > $pkgs_count_considered_outdated (seuil défini par l'utilisateur) alors on incrémente $totalNotUptodate (recense le nombre d'hôtes qui ne sont pas à jour dans le chartjs)
                                                     *  Sinon c'est $totalUptodate qu'on incrémente.
                                                     */
                                                    if ($packagesAvailableTotal >= $pkgs_count_considered_outdated) {
                                                        $totalNotUptodate++;
                                                    } else {
                                                        $totalUptodate++;
                                                    }
                                                    /**
                                                     *  Récupération du status de la dernière mise à jour (si il y en a)
                                                     */
                                                    $lastRequestedUpdate = $myhost->getLastRequestedUpdateStatus();

                                                    /**
                                                     *  Fermeture de la base de données de l'hôte
                                                     */
                                                    $myhost->closeHostDb();

                                                    /**
                                                     *  Affichage des informations de l'hôte
                                                     *  Ici le <tr> contiendra toutes les informations de l'hôte, ceci afin de pouvoir faire des recherches dessus (input 'rechercher un hôte')
                                                     */ ?>
                                                    <tr class="host-tr" hostid="<?= $id ?>" hostname="<?= $hostname ?>" os="<?= $os ?>" os_version="<?= $os_version ?>" os_family="<?= $os_family ?>" type="<?= $type ?>" kernel="<?= $kernel ?>" arch="<?= $arch ?>">
                                                        <td>
                                                            <?php
                                                            /**
                                                             *  Linupdate agent state
                                                             */
                                                            if ($agentStatus == 'running') {
                                                                echo '<img src="resources/icons/greencircle.png" class="icon-small" title="Linupdate agent state on the host: ' . $agentStatus . ' (' . $agentLastSendStatusMsg . ')." />';
                                                            }
                                                            if ($agentStatus == "disabled") {
                                                                echo '<img src="resources/icons/yellowcircle.png" class="icon-small" title="Linupdate agent state on the host: ' . $agentStatus . ' (' . $agentLastSendStatusMsg . ')." />';
                                                            }
                                                            if ($agentStatus == "stopped") {
                                                                echo '<img src="resources/icons/redcircle.png" class="icon-small" title="Linupdate agent state on the host: ' . $agentStatus . ' (' . $agentLastSendStatusMsg . ')." />';
                                                            }
                                                            if ($agentStatus == "seems-stopped") {
                                                                echo '<img src="resources/icons/redcircle.png" class="icon-small" title="Linupdate agent state on the host: ' . $agentStatus . ' (' . $agentLastSendStatusMsg . ')." />';
                                                            }
                                                            if ($agentStatus == "unknow") {
                                                                echo '<img src="resources/icons/graycircle.png" class="icon-small" title="Linupdate agent state on the host: unknow." />';
                                                            } ?>
                                                        </td>
                                                        <td>
                                                            <?php
                                                            if (preg_match('/centos/i', $os)) {
                                                                echo '<img src="resources/icons/products/centos.png" class="icon" title="' . $os . '" />';
                                                            } elseif (preg_match('/debian/i', $os)) {
                                                                echo '<img src="resources/icons/products/debian.png" class="icon" title="' . $os . '" />';
                                                            } elseif (preg_match('/ubuntu/i', $os)) {
                                                                echo '<img src="resources/icons/products/ubuntu.png" class="icon" title="' . $os . '" />';
                                                            } elseif (preg_match('/mint/i', $os)) {
                                                                echo '<img src="resources/icons/products/ubuntu.png" class="icon" title="' . $os . '" />';
                                                            } else {
                                                                echo '<img src="resources/icons/products/tux.png" class="icon" title="' . $os . '" />';
                                                            } ?>
                                                        </td>
                                                        <td>
                                                            <?php
                                                            /**
                                                             *  Print hostname and IP, with more infos about the host in the tooltip box
                                                             */
                                                            $tooltip  = 'Hostname: '. $hostname . '&#10;';
                                                            $tooltip .= 'IP: '. $ip . '&#10;';
                                                            $tooltip .= 'OS Family: '. $os_family . '&#10;';
                                                            $tooltip .= 'OS: '. $os . ' ' . $os_version . '&#10;';
                                                            $tooltip .= 'Kernel: '. $kernel . '&#10;';
                                                            $tooltip .= 'Arch: '. $arch . '&#10;';
                                                            $tooltip .= 'Profile: '. $profile . '&#10;';
                                                            $tooltip .= 'Env: '. $env . '&#10;';
                                                            echo '<span title="' . $tooltip . '">' . $hostname . ' (' . $ip . ')</span>'; ?>
                                                        </td>
                                                        <td class="hostType-td">
                                                            <span title="Type <?=$type?>"><?=$type?></span>
                                                        </td>
                                                        <td class="packagesCount-td" title="<?=$packagesInstalledTotal . ' installed package(s) on this host.'?>">
                                                            <span><?= $packagesInstalledTotal ?></span>
                                                        </td>
                                                        <td class="packagesCount-td" title="<?=$packagesAvailableTotal . ' available update(s) on this host.'?>">
                                                            <?php
                                                            if ($packagesAvailableTotal >= $pkgs_count_considered_critical) {
                                                                echo '<span class="bkg-red">' . $packagesAvailableTotal . '</span>';
                                                            } elseif ($packagesAvailableTotal >= $pkgs_count_considered_outdated) {
                                                                echo '<span class="bkg-yellow">' . $packagesAvailableTotal . '</span>';
                                                            } else {
                                                                echo '<span>' . $packagesAvailableTotal . '</span>';
                                                            } ?>
                                                        </td>
                                                        <td title="Check the details for this host.">
                                                            <span class="printHostDetails pointer" host-id="<?=$id?>">Details</span><a href="/host?id=<?=$id?>" target="_blank" rel="noopener noreferrer"><img src="resources/icons/external-link.svg" class="icon-lowopacity" /></a>
                                                        </td>
                                                        <?php
                                                        if (IS_ADMIN) : ?>
                                                            <td title="Select <?=$hostname?>">
                                                                <input type="checkbox" class="js-host-checkbox icon-verylowopacity" name="checkbox-host[]" group="<?=$groupName?>" value="<?=$id?>">
                                                            </td>
                                                            <?php
                                                        endif ?>
                                                        <td class="host-update-status">
                                                            <?php
                                                            /**
                                                             *  Status de la dernière demande
                                                             */
                                                            if (!empty($lastRequestedUpdate)) {
                                                                if ($lastRequestedUpdate['Type'] == 'packages-update') {
                                                                    $updateType = 'Packages update';
                                                                }
                                                                if ($lastRequestedUpdate['Type'] == 'general-status-update') {
                                                                    $updateType = 'Sending general info.';
                                                                }
                                                                if ($lastRequestedUpdate['Type'] == 'packages-status-update') {
                                                                    $updateType = 'Sending packages state';
                                                                }
                                                                if ($lastRequestedUpdate['Status'] == 'requested') {
                                                                    $updateStatus = 'requested';
                                                                }
                                                                if ($lastRequestedUpdate['Status'] == 'running') {
                                                                    $updateStatus = 'running<img src="resources/images/loading.gif" class="icon" />';
                                                                }
                                                                if ($lastRequestedUpdate['Status'] == 'done') {
                                                                    $updateStatus = 'done';
                                                                }
                                                                if ($lastRequestedUpdate['Status'] == 'error') {
                                                                    $updateStatus = 'has failed';
                                                                }
                                                                /**
                                                                 *  Si la demande de mise à jour a été faite il y a plusieurs jours ou a été faite il y a +10min alors on affiche le message en jaune, l'hôte distant n'a peut être pas reçu ou traité la demande
                                                                 */
                                                                if ($lastRequestedUpdate['Status'] == 'requested' or $lastRequestedUpdate['Status'] == 'running') {
                                                                    if ($lastRequestedUpdate['Date'] != DATE_YMD or $lastRequestedUpdate['Time'] <= date('H:i:s', strtotime(date('H:i:s') . ' - 10 minutes'))) {
                                                                        echo '<span class="yellowtext" title="The request does not seem to have been taken into account by the host (requested on ' . DateTime::createFromFormat('Y-m-d', $lastRequestedUpdate['Date'])->format('d-m-Y') . ' at ' . $lastRequestedUpdate['Time'] . ')">' . $updateType . ' ' . $updateStatus . '</span>';
                                                                    } else {
                                                                        echo '<span title="On ' . DateTime::createFromFormat('Y-m-d', $lastRequestedUpdate['Date'])->format('d-m-Y') . ' at ' . $lastRequestedUpdate['Time'] . '">' . $updateType . ' ' . $updateStatus . '</span>';
                                                                    }
                                                                }
                                                                if ($lastRequestedUpdate['Status'] == 'error') {
                                                                    echo '<span class="redtext" title="On ' . DateTime::createFromFormat('Y-m-d', $lastRequestedUpdate['Date'])->format('d-m-Y') . ' at ' . $lastRequestedUpdate['Time'] . '">' . $updateType . ' ' . $updateStatus . '</span>';
                                                                }
                                                            } ?>
                                                        </td>
                                                        <td class="host-additionnal-info">
                                                        </td>
                                                    </tr>
                                                    <?php
                                                } ?>
                                            </tbody>
                                        </table>
                                        <?php
                                    } else {
                                        echo '<table class="hosts-table-empty"><tr><td class="lowopacity">(empty)</td></tr></table>';
                                    } ?>
                                </div>
                                <?php
                            endforeach; ?>
                        </div>
                        <?php
                    endif; ?>
                </div>
            </div>
            <?php
        endif ?>
</section>

<?php
if (IS_ADMIN) : ?>
    <div id="hostsSettingsDiv" class="param-slide-container">
        <div class="param-slide">
            <img id="hostsSettingsDivCloseButton" title="Close" class="close-btn lowopacity float-right" src="resources/icons/close.svg" />
            <h3>HOSTS DISPLAY SETTINGS</h3>
            <form id="hostsSettingsForm" action="/hosts" method="post" autocomplete="off">
                <table>
                    <tr>
                        <td>Display a yellow label when total available update is greater than or equal to:</td>
                        <td><input type="number" class="input-small" name="settings-pkgs-considered-outdated" value="<?=$pkgs_count_considered_outdated?>" /></td>
                    </tr>
                    <tr>
                        <td>Display a red label when total available update is greater than or equal to:</td>
                        <td><input type="number" class="input-small" name="settings-pkgs-considered-critical" value="<?=$pkgs_count_considered_critical?>" /></td>
                    </tr>
                </table>
                <br>
                <button class="btn-large-green">Save</button>
            </form>
        </div>
    </div>
    <div id="groupsHostDiv" class="param-slide-container">
        <div class="param-slide">
            <img id="groupsDivCloseButton" title="Close" class="close-btn lowopacity float-right" src="resources/icons/close.svg" />
            
            <h3>GROUPS</h3>
            
            <h4><b>Create a new group</b></h4>

            <form id="newGroupForm" autocomplete="off">
                <input id="newGroupInput" type="text" class="input-medium" placeholder="Group name" /></td>
                <button type="submit" class="btn-xxsmall-green" title="Add">+</button></td>
            </form>
            
            <br>
            <?php
            /**
             *  Getting all groups names
             */
            $groupsList = $group->listAllName();

            if (!empty($groupsList)) : ?>
                <h4><b>Current groups</b></h4>
                <div class="groups-list-container">
                    <?php
                    foreach ($groupsList as $groupName) : ?>
                        <div class="header-container">
                            <div class="header-blue-min">
                                <form class="groupForm" groupname="<?= $groupName ?>" autocomplete="off">
                                    <input type="hidden" name="actualGroupName" value="<?= $groupName ?>" />
                                    <table class="table-large">
                                        <tr>
                                            <td>
                                                <input class="groupFormInput input-medium invisibleInput-blue" groupname="<?= $groupName ?>" type="text" value="<?= $groupName ?>" />
                                            </td>
                                            <td class="td-fit">
                                                <img class="groupConfigurationButton icon-mediumopacity" name="<?= $groupName ?>" title="<?= $groupName ?> group configuration" src="resources/icons/cog.svg" />
                                                <img src="resources/icons/bin.svg" class="deleteGroupButton icon-lowopacity" name="<?= $groupName ?>" title="Delete <?= $groupName ?> group" />
                                            </td>
                                        </tr>
                                    </table>
                                </form>
                            </div>
                            <div id="groupConfigurationDiv-<?= $groupName ?>" class="hide">
                                <form class="groupHostsForm" groupname="<?= $groupName ?>" autocomplete="off">
                                    <div class="detailsDiv">
                                        <h5>Hosts</h5>
                                        <div class="flex align-content-center">
                                            <?php $myhost->selectServers($groupName); ?>
                                            <button type="submit" class="btn-xxsmall-green" title="Add and save">+</button>
                                        </div>
                                    </div>
                                </form>
                            </div>
                        </div>
                        <?php
                    endforeach ?>
                    </div>
                </div>
                <?php
            endif ?>
        </div>
    </div>
    <?php
endif ?>

<?php
/**
 *  ChartJS
 */

/**
 *  Hosts chart
 */
$labels = "'Up to date', 'Need update'";
$datas = "'$totalUptodate', '$totalNotUptodate'";
$backgrounds = "'rgb(75, 192, 192)','rgb(255, 99, 132)'";
$title = '';
$chartId = 'hosts-count-chart';

include(ROOT . '/views/includes/hosts-pie-chart.inc.php');

/**
 *  Profiles chart
 */
if (!empty($profilesList)) {
    $profileNameList = '';
    $profileCountList = '';
    $profileBackgroundColor = '';

    foreach ($profilesList as $profile) {
        if (empty($profile['Profile'])) {
            $profileNameList .= "'Unknow',";
        } else {
            $profileNameList .= "'" . $profile['Profile'] . "',";
        }
        $profileCountList .= "'" . $profile['Profile_count'] . "',";
        $profileBackgroundColor .= "'" . $mycolor->randomColor() . "',";
    }

    $labels = rtrim($profileNameList, ',');
    $datas = rtrim($profileCountList, ',');
    $backgrounds = rtrim($profileBackgroundColor, ',');
    $title = '';
    $chartId = 'hosts-profile-chart';

    include(ROOT . '/views/includes/hosts-bar-chart.inc.php');
}

/**
 *  OS chart
 */
if (!empty($osList)) {
    $osNameList = '';
    $osCountList = '';
    $osBackgroundColor = '';

    foreach ($osList as $os) {
        if (empty($os['Os'])) {
            $osNameList .= "'Unknow',";
        } else {
            $osNameList .= "'" . ucfirst($os['Os']) . " " . $os['Os_version'] . "',";
        }
        $osCountList .= "'" . $os['Os_count'] . "',";
        $osBackgroundColor .= "'" . $mycolor->randomColor() . "',";
    }

    $labels = rtrim($osNameList, ',');
    $datas = rtrim($osCountList, ',');
    $backgrounds = rtrim($osBackgroundColor, ',');
    $title = '';
    $chartId = 'hosts-os-chart';

    include(ROOT . '/views/includes/hosts-bar-chart.inc.php');
}

/**
 *  Arch chart
 */
if (!empty($archList)) {
    $archNameList = '';
    $archCountList = '';
    $archBackgroundColor = '';

    foreach ($archList as $arch) {
        if (empty($arch['Arch'])) {
            $archNameList .= "'Unknow',";
        } else {
            $archNameList .= "'" . $arch['Arch'] . "',";
        }
        $archCountList .= "'" . $arch['Arch_count'] . "',";
        $archBackgroundColor .= "'" . $mycolor->randomColor() . "',";
    }

    $labels = rtrim($archNameList, ',');
    $datas = rtrim($archCountList, ',');
    $backgrounds = rtrim($archBackgroundColor, ',');
    $title = '';
    $chartId = 'hosts-arch-chart';

    include(ROOT . '/views/includes/hosts-pie-chart.inc.php');
}

/**
 *  Envs chart
 */
if (!empty($envsList)) {
    $envNameList = '';
    $envCountList = '';
    $envBackgroundColor = '';

    foreach ($envsList as $env) {
        if (empty($env['Env'])) {
            $envNameList .= "'Unknow',";
        } else {
            $envNameList .= "'" . $env['Env'] . "',";
        }
        $envCountList .= "'" . $env['Env_count'] . "',";

        if ($env['Env'] == LAST_ENV) {
            $envBackgroundColor .= "'rgb(255, 99, 132)',";
        } else {
            $envBackgroundColor .= "'" . $mycolor->randomColor() . "',";
        }
    }

    $labels = rtrim($envNameList, ',');
    $datas = rtrim($envCountList, ',');
    $backgrounds = rtrim($envBackgroundColor, ',');
    $title = '';
    $chartId = 'hosts-env-chart';

    include(ROOT . '/views/includes/hosts-pie-chart.inc.php');
}

/**
 *  Agent status chart
 */
if (!empty($agentStatusList)) {
    $agentStatusNameList = '';
    $agentStatusCountList = '';
    $agentBackgroundColor = '';

    if (!empty($agentStatusList['Linupdate_agent_status_online_count'])) {
        $agentStatusNameList .= "'Online',";
        $agentStatusCountList .= "'" . $agentStatusList['Linupdate_agent_status_online_count'] . "',";
        $agentBackgroundColor .= "'#24d794',";
    }

    if (!empty($agentStatusList['Linupdate_agent_status_seems_stopped_count'])) {
        $agentStatusNameList .= "'Seems stopped',";
        $agentStatusCountList .= "'" . $agentStatusList['Linupdate_agent_status_seems_stopped_count'] . "',";
        $agentBackgroundColor .= "'#e0b05f',";
    }

    if (!empty($agentStatusList['Linupdate_agent_status_stopped_count'])) {
        $agentStatusNameList .= "'Stopped',";
        $agentStatusCountList .= "'" . $agentStatusList['Linupdate_agent_status_stopped_count'] . "',";
        $agentBackgroundColor .= "'rgb(255, 99, 132)',";
    }

    if (!empty($agentStatusList['Linupdate_agent_status_disabled_count'])) {
        $agentStatusNameList .= "'Disabled',";
        $agentStatusCountList .= "'" . $agentStatusList['Linupdate_agent_status_disabled_count'] . "',";
        $agentBackgroundColor .= "'rgb(255, 99, 132)',";
    }

    $labels = rtrim($agentStatusNameList, ',');
    $datas = rtrim($agentStatusCountList, ',');
    $backgrounds = rtrim($agentBackgroundColor, ',');
    $title = '';
    $chartId = 'hosts-agent-status-chart';

    include(ROOT . '/views/includes/hosts-pie-chart.inc.php');
}

/**
 *  Agent release version chart
 */
if (!empty($agentVersionList)) {
    $agentNameList = '';
    $agentCountList = '';
    $agentBackgroundColor = '';

    foreach ($agentVersionList as $agent) {
        if (empty($agent['Linupdate_version'])) {
            $agentNameList .= "'Unknow',";
        } else {
            $agentNameList .= "'" . $agent['Linupdate_version'] . "',";
        }
        $agentCountList .= "'" . $agent['Linupdate_version_count'] . "',";
        $agentBackgroundColor .= "'" . $mycolor->randomColor() . "',";
    }

    $labels = rtrim($agentNameList, ',');
    $datas = rtrim($agentCountList, ',');
    $backgrounds = rtrim($agentBackgroundColor, ',');
    $title = '';
    $chartId = 'hosts-agent-version-chart';

    include(ROOT . '/views/includes/hosts-pie-chart.inc.php');
} ?>