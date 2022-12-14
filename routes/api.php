<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

use App\Http\Controllers\UserController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::post('login',    [UserController::class, 'login']);
Route::post('register', [UserController::class, 'register']);
Route::get('logout',    [UserController::class, 'logout'])->middleware('auth:sanctum');
Route::get('check',     [UserController::class, 'check'])->middleware('auth:sanctum');
Route::get('user',      [UserController::class, 'user'])->middleware('auth:sanctum');