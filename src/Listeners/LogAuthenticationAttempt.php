<?php

namespace Yadahan\AuthenticationLog\Listeners;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Yadahan\AuthenticationLog\AuthenticationLog;
use Yadahan\AuthenticationLog\Notifications\NewDevice;

class LogAuthenticationAttempt
{
    /**
     * The request.
     *
     * @var \Illuminate\Http\Request
     */
    public $request;

    /**
     * Create the event listener.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    /**
     * Handle the event.
     *
     * @param  Login  $event
     * @return void
     */
    public function handle(Attempting $event)
    {
        $user = $event->user;
        $ip = $this->request->ip();
        $userAgent = $this->request->userAgent();
        $known = $user->authentications()->whereIpAddress($ip)->whereUserAgent($userAgent)->first();

        $authenticationLog = new AuthenticationLog([
            'ip_address' => $ip,
            'user_agent' => $userAgent,
        ]);

        $user->authentications()->save($authenticationLog);

    }
}
