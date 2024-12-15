<?php

namespace App\Services;

use App\Models\User;
use App\Mail\VerifyEmail;
use Illuminate\Support\Str;
use App\Traits\ApiResponser;
use App\Traits\FileUploadTrait;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Auth;
use Carbon\Carbon;
use Exception;

class AuthService
{
    use ApiResponser, FileUploadTrait;

    public function register($data)
    {
        try {
            $validator = Validator::make($data, [
                'full_name' => 'required|string|max:255',
                'email' => 'required|string|email|max:255|unique:users,email',
                'password' => 'required|string|min:8|max:255',
                'phone' => 'required|string|unique:users,phone',
                'profile_photo' => 'required|image|max:2048'
            ]);

            if ($validator->fails()) {
                return $this->errorResponse($validator->errors(), 400);
            }

            $verificationCode = Str::random(6);

            if (!$this->sendVerificationEmail($data['email'], $verificationCode)) {
                throw new Exception('Failed to send verification code via Email.');
            }

            $cacheKey = 'user_registration_' . $data['email'];
            Cache::put($cacheKey, [
                'full_name' => $data['full_name'],
                'email' => $data['email'],
                'password' => Hash::make($data['password']),
                'phone' => $data['phone'],
                'profile_photo' => $this->uploadFile($data['profile_photo'], 'profile_photos'),
                'verification_code' => $verificationCode,
                'ip_address' => request()->ip(),
            ], now()->addMinutes(10));

            return $this->successResponse('Registered successfully. Please check your email for the verification code.');

        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    private function sendVerificationEmail($email, $verificationCode)
    {
        $emailData = new VerifyEmail($verificationCode);

        try {
            Mail::to($email)->send($emailData);
            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    public function verifyEmail($email, $verificationCode)
    {
        try {
            $cacheKey = 'user_registration_' . $email;
            $cachedUser = Cache::get($cacheKey);

            if (!$cachedUser || $cachedUser['verification_code'] !== $verificationCode || request()->ip() !== $cachedUser['ip_address']) {
                throw new Exception('Invalid coordination.');
            }

            $user = User::create([
                'full_name' => $cachedUser['full_name'],
                'email' => $cachedUser['email'],
                'password' => $cachedUser['password'],
                'phone' => $cachedUser['phone'],
                'profile_photo' => $cachedUser['profile_photo'],
                'verification_code' => null,
                'verified_at' => now(),
                'ip_address' => $cachedUser['ip_address'],
            ]);

            Cache::forget($cacheKey);

            $tokenResult = $this->createAccessTokenAndRefreshToken($user);

            return $this->successResponse('Email verified successfully.', [
                'user' => $user,
                'access_token' => $tokenResult['access_token'],
                'access_token_expiry' => $tokenResult['access_token_expiry'],
            ]);
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 400);
        }
    }

    public function login($data)
    {
        try {
            $validator = Validator::make($data, [
                'identifier' => 'required|string|max:255',
                'password' => 'required|string|min:8|max:255',
            ]);

            if ($validator->fails()) {
                return $this->errorResponse($validator->errors(), 400);
            }

            $credentials = [];
            if (filter_var($data['identifier'], FILTER_VALIDATE_EMAIL)) {
                $credentials = ['email' => $data['identifier'], 'password' => $data['password']];
            } else {
                $credentials = ['phone' => $data['identifier'], 'password' => $data['password']];
            }

            if (!Auth::attempt($credentials)) {
                throw new Exception('Invalid credentials.');
            }

            $user = Auth::user();
            $tokenResult = $this->createAccessTokenAndRefreshToken($user);

            return $this->successResponse('Login successful.', [
                'user' => $user,
                'access_token' => $tokenResult['access_token'],
                'access_token_expiry' => $tokenResult['access_token_expiry'],
            ]);
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 401);
        }
    }

    public function logout()
    {
        try {
            $user = Auth::user();
            $user->tokens()->delete();

            return $this->successResponse('Logged out successfully.');
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function refreshToken($refreshToken)
    {
        try {
            $user = Auth::user();
            $user->tokens()->delete();

            $refreshToken = $user->createToken('refresh_token', ['*'], Carbon::now()->addMinutes(20));

            return $this->successResponse('Token refreshed successfully.', [
                'refresh_token' => $refreshToken->plainTextToken,
                'refresh_token_expiry' => $refreshToken->accessToken->expires_at,
            ]);
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    private function createAccessTokenAndRefreshToken($user)
    {
        try {
            $accessToken = $user->createToken('access_token', ['*'], Carbon::now()->addMinutes(10));

            return [
                'access_token' => $accessToken->plainTextToken,
                'access_token_expiry' => $accessToken->accessToken->expires_at,
            ];
        } catch (Exception $e) {
            throw new Exception('Failed to create tokens.');
        }
    }
}
