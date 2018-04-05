<?php
namespace Yuca\SSO;

/**
 * Single sign-on server.
 *
 * The SSO server is responsible of managing users sessions which are available for brokers.
 *
 * To use the SSO server, extend this class and implement the abstract methods.
 * This class may be used as controller in an MVC application.
 */
abstract class Server
{
    /**
     * @var array
     */
    protected $options = [];

    /**
     * @var string
     */
    protected $returnType;

    /**
     * @var mixed
     */
    protected $brokerId;


    /**
     * Class constructor
     *
     * @param array $options
     */
    public function __construct(array $options = [])
    {
        $this->options = $options + $this->options;
    }

    /**
     * Start the session for broker requests to the SSO server
     */
    public function startBrokerSession()
    {
        // Validate the allowed IPs
        if (isset($this->options['allowed_ips']) && is_array($this->options['allowed_ips']) && count($this->options['allowed_ips']) > 0) {
            if (isset($_REQUEST['referer_ip'])) {
                if (!in_array($_REQUEST['referer_ip'], $this->options['allowed_ips'])) {
                    return $this->fail('Restricted IP', 400);
                }
            } else {
               return $this->fail('Missing referer IP', 400);
            }
        }

        if (isset($this->brokerId)) return;

        $sid = $this->getBrokerSessionID();

        if ($sid === false) {
            return $this->fail("Broker didn't send a session key", 400);
        }

        $linkedId = $this->getCacheData($sid);

        if (!$linkedId) {
            return $this->fail("The broker session id isn't attached to a user session", 403);
        }

        if ($this->isSessionStarted()) {
            if ($linkedId !== $this->sessionId()) throw new \Exception("Session has already started", 400);
            return;
        }

        $this->sessionId($linkedId);
        $this->sessionStart();

        $this->brokerId = $this->validateBrokerSessionId($sid);
    }

    /**
     * Get session ID from header Authorization or from $_GET/$_POST
     */
    protected function getBrokerSessionID()
    {
        if (function_exists('getallheaders')) {
            $headers = getallheaders();

            if (isset($headers['Authorization']) &&  strpos($headers['Authorization'], 'Bearer') === 0) {
                $headers['Authorization'] = substr($headers['Authorization'], 7);
                return $headers['Authorization'];
            }
        }

        if (isset($_GET['access_token'])) {
            return $_GET['access_token'];
        }

        if (isset($_POST['access_token'])) {
            return $_POST['access_token'];
        }

        return false;
    }

    /**
     * Validate the broker session id
     *
     * @param string $sid session id
     * @return string  the broker id
     */
    protected function validateBrokerSessionId($sid)
    {
        $matches = null;

        if (!preg_match('/^SSO-(\w*+)-(\w*+)-([a-z0-9]*+)$/', $this->getBrokerSessionID(), $matches)) {
            return $this->fail("Invalid session id");
        }

        $brokerId = $matches[1];
        $token = $matches[2];

        if ($this->generateSessionId($brokerId, $token) != $sid) {
            return $this->fail("Checksum failed: Client IP address may have changed", 403);
        }

        return $brokerId;
    }

    /**
     * Start the session when a user visits the SSO server
     */
    protected function startUserSession()
    {
        if (!$this->isSessionStarted()) $this->sessionStart();
    }

    /**
     * Generate session id from session token
     *
     * @param string $brokerId
     * @param string $token
     * @return string
     */
    protected function generateSessionId($brokerId, $token)
    {
        $broker = $this->getBrokerInfo($brokerId);

        if (!isset($broker)) return null;

        return "SSO-{$brokerId}-{$token}-" . hash('sha256', 'session' . $token . $broker['secret']);
    }

    /**
     * Generate session id from session token
     *
     * @param string $brokerId
     * @param string $token
     * @return string
     */
    protected function generateAttachChecksum($brokerId, $token)
    {
        $broker = $this->getBrokerInfo($brokerId);

        if (!isset($broker)) return null;

        return hash('sha256', 'attach' . $token . $broker['secret']);
    }


    /**
     * Detect the type for the HTTP response.
     * Should only be done for an `attach` request.
     */
    protected function detectReturnType()
    {
        if (!empty($_GET['return_url'])) {
            $this->returnType = 'redirect';
        } elseif (!empty($_GET['callback'])) {
            $this->returnType = 'jsonp';
        } elseif (strpos($_SERVER['HTTP_ACCEPT'], 'image/') !== false) {
            $this->returnType = 'image';
        } elseif (strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false) {
            $this->returnType = 'json';
        }
    }

    /**
     * Attach a user session to a broker session
     */
    public function attach()
    {
        $this->detectReturnType();

        if (empty($_REQUEST['broker'])) return $this->fail("No broker specified", 400);
        if (empty($_REQUEST['token'])) return $this->fail("No token specified", 400);

        if (!$this->returnType) return $this->fail("No return url specified", 400);

        $checksum = $this->generateAttachChecksum($_REQUEST['broker'], $_REQUEST['token']);

        if (empty($_REQUEST['checksum']) || $checksum != $_REQUEST['checksum']) {
            return $this->fail("Invalid checksum", 400);
        }

        $this->startUserSession();
        $sid = $this->generateSessionId($_REQUEST['broker'], $_REQUEST['token']);

        $this->setCacheData($sid, $this->sessionId());
        $this->outputAttachSuccess();
        exit();
    }

    /**
     * Output on a successful attach
     */
    protected function outputAttachSuccess()
    {
        if ($this->returnType === 'image') {
            $this->outputImage();
        }

        if ($this->returnType === 'json') {
            header('Content-type: application/json; charset=UTF-8');
            echo json_encode(['success' => 'attached']);
        }

        if ($this->returnType === 'jsonp') {
            $data = json_encode(['success' => 'attached']);
            echo $_REQUEST['callback'] . "($data, 200);";
        }

        if ($this->returnType === 'redirect') {
            $url = $_REQUEST['return_url'];
            header("Location: $url", true, 307);
            echo "You're being redirected to <a href='{$url}'>$url</a>";
        }
    }

    /**
     * Output a 1x1px transparent image
     */
    protected function outputImage()
    {
        header('Content-Type: image/png');
        echo base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABAQ'
            . 'MAAAAl21bKAAAAA1BMVEUAAACnej3aAAAAAXRSTlMAQObYZg'
            . 'AAAApJREFUCNdjYAAAAAIAAeIhvDMAAAAASUVORK5CYII=');
    }


    /**
     * Authenticate
     */
    public function login()
    {
        $this->startBrokerSession();

        if (empty($_POST['username'])) $this->fail("No username specified", 400);
        if (empty($_POST['password'])) $this->fail("No password specified", 400);

        $validation = $this->authenticate($_POST['username'], $_POST['password']);

        if ($validation->failed()) {
            return $this->fail($validation->getError(), 400);
        }

        $this->setSessionData('sso_user', $_POST['username']);
        $this->userInfo();
    }

    /**
     * Log out
     */
    public function logout()
    {
        $this->startBrokerSession();
        $this->setSessionData('sso_user', null);

        header('Content-type: application/json; charset=UTF-8');
        http_response_code(204);
        exit();
    }

    /**
     * Ouput user information as json.
     */
    public function userInfo()
    {
        $this->startBrokerSession();
        $user = null;

        $username = $this->getSessionData('sso_user');

        if ($username) {
            $user = $this->getUserInfo($username);
            if (!$user) return $this->fail("User not found", 500); // Shouldn't happen
        }

        header('Content-type: application/json; charset=UTF-8');
        echo json_encode($user);
        exit();
    }

    /**
     * An error occured.
     *
     * @param string $message
     * @param int    $http_status
     */
    protected function fail($message, $http_status = 500)
    {
        if (!empty($this->options['fail_exception'])) {
            throw new Exception($message, $http_status);
        }

        if ($http_status === 500) trigger_error($message, E_USER_WARNING);

        if ($this->returnType === 'jsonp') {
            echo $_REQUEST['callback'] . "(" . json_encode(['error' => $message]) . ", $http_status);";
            exit();
        }

        if ($this->returnType === 'redirect') {
            $url = $_REQUEST['return_url'] . '?sso_error=' . $message;
            header("Location: $url", true, 307);
            echo "You're being redirected to <a href='{$url}'>$url</a>";
            exit();
        }

        http_response_code($http_status);
        header('Content-type: application/json; charset=UTF-8');

        echo json_encode(['error' => $message]);
        exit();
    }

    /**
     * Set cache data
     *
     * @param string $key
     * @param string $value
     */
    abstract protected function setCacheData($key, $value);

    /**
     * Get cache data
     *
     * @param type $key
     */
    abstract protected function getCacheData($key);

    /**
     * Check the session status
     * @return boolean 
     */
    abstract protected function isSessionStarted();

    /**
     * Start session
     */
    abstract protected function sessionStart();

    /**
     * Get/set session id
     * @param  string $id 
     * @return string
     */
    abstract protected function sessionId($id = null);

    /**
     * Set session data
     *
     * @param string $key
     * @param string $value
     */
    abstract protected function setSessionData($key, $value);

    /**
     * Get session data
     *
     * @param type $key
     */
    abstract protected function getSessionData($key);

    /**
     * Authenticate using user credentials
     *
     * @param string $username
     * @param string $password
     * @return \Jasny\ValidationResult
     */
    abstract protected function authenticate($username, $password);

    /**
     * Get the secret key and other info of a broker
     *
     * @param string $brokerId
     * @return array
     */
    abstract protected function getBrokerInfo($brokerId);

    /**
     * Get the information about a user
     *
     * @param string $username
     * @return array|object
     */
    abstract protected function getUserInfo($username);
}