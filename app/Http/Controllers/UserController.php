<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Http\Request;

use App\Models\User;

class UserController extends Controller
{
    public function login(Request $request) {
        $request->validate([
            'email'     => 'required|email',
            'password'  => 'required',
            'device'    => 'required',
        ]);

        if (!Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
            return response('UNAURTHORIZED', 401);
        }

        $user = Auth::user();

        return response($user->createToken($request->device)->plainTextToken, 200);
    }

    public function register(Request $request) {
        $request->validate([
            'name'      => 'required',
            'email'     => 'required|email|unique:users',
            'password'  => 'required',
            'device'    => 'required',
        ]);

        $user = User::create([
            'name'      => $request->name,
            'email'     => $request->email,
            'password'  => Hash::make($request->password),
        ]);

        $user->save();

        return response($user->createToken($request->device)->plainTextToken, 200);
    }

    public function check(Request $request) {
        $user = Auth::user();

        if (!is_null($user)) {
            return response('OK', 200);
        }
        else {
            return response('UNAURTHORIZED', 401);
        }
    } 

    public function logout(Request $request) {
        $user = Auth::user();

        if (!is_null($user)) {
            $user->tokens()->delete();
            return response('OK', 200);
        }
        else {
            return response('BAD REQUEST', 400);
        }
    }

    public function user(Request $request) {
        $user = Auth::user();

        if (!is_null($user)) {
            return $user;
        }
        else {
            return response('UNAURTHORIZED', 401);
        }
    }
}