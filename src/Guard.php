<?php
namespace RouteProtection;

class Guard
{
    protected $request;

    /**
    * Route patterns that require authentication
    * @var array
    */
    protected $routes = [];

    protected $foundRoute;

    protected $accessType;

    const ALL = 'all';
    const WEB = 'web';
    const CURL = 'curl';
    const AJAX = 'ajax';

    public function __construct(\Psr\Http\Message\ServerRequestInterface $request, array $routes)
    {
        $this->request = $request;
        $this->foundRoute = $this->findRoute($routes);
        $this->accessType = $this->getAccessType();
    }

    public function isRouteProtected()
    {
        if (is_array($this->foundRoute)) {
            return true;
        }

        return false;
    }

    public function isRoleValid($role)
    {

        if ($this->accessType === self::WEB && (empty($this->foundRoute[$role]) || in_array(self::WEB, $this->foundRoute[$role]))) {
            return true;
        } elseif ($this->accessType !== self::WEB && (!empty($this->foundRoute[$role]) && in_array(self::CURL, $this->foundRoute[$role]))) {
            return true;
        } else {
            return false;
        }
    }

    public function getRoles()
    {
        return array_keys($this->foundRoute);
    }

    protected function getAccessType() {
        return empty($serverParams['HTTP_USER_AGENT']) ? self::CURL : self::WEB;
    }

    protected function findRoute(array $routes) {
        // Get server params
        $serverParams = $this->request->getServerParams();

        // Get URI
        $redirectUrl = substr($serverParams['REQUEST_URI'], -1) !== '/' ? $serverParams['REQUEST_URI'].'/' : $serverParams['REQUEST_URI'];

        // If the route requested is not found in the array containing
        // routes that require authentication then there's nothing to do
        $requiredRoutes = array_keys($routes);

        foreach ($requiredRoutes as $route) {
            if ($redirectUrl === $route) {
                return $routes[$route];
            }

            if (!$regex = $this->parseRoute($route)) {
                throw new \InvalidArgumentException("Route {$route} is invalid");
            }

            if (!empty(preg_match($regex, $redirectUrl))) {
                $this->routes[$redirectUrl] = $this->routes[$route];
                unset($this->routes[$route]);
                return $routes[$route];
            }
        }

        return false;
    }

    /**
    * Get regex representation of the registered route
    * @param  string $route Registered route
    * @return string        Regex string for the route
    */
    protected function getRegex($route)
    {
        // Invalid pattern
        if (preg_match('/[^-:\/_{}[]()a-zA-Z\d]/', $route)) {
            return false;
        }

        // Turn "(/)" into "/?"
        $route = preg_replace('#\(/\)#', '/?', $route);

        // Create capture group for ":parameter"
        $allowedParamChars = '[a-zA-Z0-9\_\-]+';

        //Replace ":parameter" with "(?<parameter>[a-zA-Z0-9\_\-]+)"
        $route = preg_replace(
            '/:(' . $allowedParamChars . ')/',
            '(?<$1>' . $allowedParamChars . ')',
            $route
        );

        // Create capture group for '{parameter}'
        // Replace "{parameter}" with "(?<parameter>[a-zA-Z0-9\_\-]+)"
        $route = preg_replace(
            '/{('. $allowedParamChars .')}/',
            '(?<$1>' . $allowedParamChars . ')',
            $route
        );

        // Add start and end matching
        $routeAsRegex = "@^" . $route . "$@D";

        return $routeAsRegex;
    }
}
