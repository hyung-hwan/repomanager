<?php

namespace Controllers\Api\Snapshot;

use Exception;
use Datetime;

class Snapshot extends \Controllers\Api\Controller
{
    private $snapId;
    private $postFiles;

    public function execute()
    {
        $myrepo = new \Controllers\Repo\Repo();
        $mypackage = new \Controllers\Repo\Package();

        /**
         *  Snapshot actions are only allowed for API admins
         */
        if (!IS_API_ADMIN) {
            throw new Exception('You are not allowed to access this resource.');
        }

        /**
         *  Retrieve snapshot Id if any
         */
        if (!empty($this->uri[4])) {
            $this->snapId = $this->uri[4];
        }

        /**
         *  Retrieve action if any
         */
        if (!empty($this->uri[5])) {
            $this->action = $this->uri[5];
        }

        /**
         *  Retrieve uploaded FILES if any
         */
        if (!empty($_FILES)) {
            $this->postFiles = $_FILES;
        }

        /**
         *  If a snapshot Id is specified
         *  https://repomanager.mydomain.net/api/v2/snapshot/$this->snapId/
         */
        if (!empty($this->snapId)) {
            if ($this->method == 'POST') {
                /**
                 *  Upload packages to a snapshot
                 *  https://repomanager.mydomain.net/api/v2/snapshot/$this->snapId/upload
                 */
                if ($this->action == 'upload' and !empty($this->postFiles)) {
                    $mypackage->upload($this->snapId, $this->postFiles);

                    return array('results' => 'Packages uploaded successfully');
                }
            }

            if ($this->method == 'PUT') {
                /**
                 *  Reconstruct a snapshot
                 *  https://repomanager.mydomain.net/api/v2/snapshot/$this->snapId/reconstruct
                 */
                if ($this->action == 'reconstruct') {
                }
            }
        }

        throw new Exception('Invalid request');
    }
}
