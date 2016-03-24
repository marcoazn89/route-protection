# route-protection
Module to protect your routes based on roles + access type

OAuth2 configuration
--------------------
```php
// Example. I bet you might want to request to make them work also based on GET, POST, etc, but for now get creative with the roles.

$config =  [
    '/api/account[/]' => [
      'admin' => ['web','curl']
    ],
    '/api/account/{id}[/]' => [
      'admin' => ['web','curl'],
      'partner' => ['web'],
      'user' => ['web']
    ]
]
```
