<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(Request $resquest) {
        $fields = $resquest->validate([
            'name' => 'required|string',
            'email' => 'required|string|unique:users,email',
            'password' => 'required|string|confirmed'
        ]);

        $user = User::create([
            'name' => $fields['name'],
            'email' => $fields['email'],
            'password' => bcrypt($fields['password'])
        ]);

        $token = $user->createToken('myapptoken');

        $response = [
            'user' => $user,
            'token' => $token->plainTextToken,
            'expired_at' => $token->accessToken->expired_at
        ];

        return response($response, 201);
    }

    public function logout(Request $resquest) {
        auth()->user()->tokens()->delete();

        return response ('Logged out');
    }

    public function login(Request $resquest) {
        $fields = $resquest->validate([
            'email' => 'required|string',
            'password' => 'required|string'
        ]);

        //Check Email
        $user = User::where('email', $fields['email'])->first();

        //Check password
        if(!$user || !Hash::check($fields['password'], $user->password)) {
            return response ([
                'message' => 'Wrong credentials'
            ], 401);
        }
        
        $token = $user->createToken('myapptoken')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, 201);
    }
}
