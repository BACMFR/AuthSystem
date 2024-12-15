<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\RegisterRequest;
use App\Http\Requests\LoginRequest;
use App\Services\AuthService;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    protected $authService;

    public function __construct(AuthService $authService)
    {
        $this->authService = $authService;
    }

    public function register(RegisterRequest $request)
    {
        $data = $request->all();
        $data['ip_address'] = $request->ip();
        $response = $this->authService->register($data);

        return response()->json($response, $response['status_code']);
    }

    public function login(LoginRequest $request)
    {
        $data = $request->all();
        $response = $this->authService->login($data);

        return response()->json($response, $response['status_code']);
    }

    public function verifyEmail(Request $request)
    {
        $email = $request->input('email');
        $verificationCode = $request->input('verification_code');
        $response = $this->authService->verifyEmail($email, $verificationCode);

        return response()->json($response, $response['status_code']);
    }

    public function logout(Request $request)
    {
        $response = $this->authService->logout();

        return response()->json($response, $response['status_code']);
    }

    public function refreshToken(Request $request)
    {
        $refreshToken = $request->input('refresh_token');
        $response = $this->authService->refreshToken($refreshToken);

        return response()->json($response, $response['status_code']);
    }
}
