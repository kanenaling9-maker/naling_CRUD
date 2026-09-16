<?php
defined('PREVENT_DIRECT_ACCESS') OR exit('No direct script access allowed');

class Auth extends Controller
{
    public function __construct()
    {
        parent::__construct();
        $this->call->library('session');
        $this->call->helper('url');
    }

    public function login()
    {
        if ($this->session->userdata('user_id')) {
            return $this->response->redirect(site_url('products'));
        }

        $error = null;
        if ($this->request->is_post()) {
            $login = trim((string) $this->request->post('login'));
            $password = (string) $this->request->post('password');

            if ($login === 'admin' && $password === 'admin') {
                session_regenerate_id(true);
                $this->session->set_userdata([
                    'user_id' => 1,
                    'username' => 'admin',
                ]);
                return $this->response->redirect(site_url('products'));
            }
            $error = 'Invalid login credentials.';
        }

        $this->call->view('login', ['error' => $error]);
    }

    public function register()
    {
        if ($this->session->userdata('user_id')) {
            return $this->response->redirect(site_url('products'));
        }

        $this->call->model('UsersModel');
        $error = null;
        if ($this->request->is_post()) {
            $username = trim((string) $this->request->post('username'));
            $email = trim((string) $this->request->post('email'));
            $password = (string) $this->request->post('password');

            if ($username === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 6) {
                $error = 'Use a username, valid email, and password of at least 6 characters.';
            } elseif ($this->UsersModel->find_by('username', $username) || $this->UsersModel->find_by('email', $email)) {
                $error = 'That username or email is already registered.';
            } else {
                $this->UsersModel->insert([
                    'username' => $username,
                    'email' => $email,
                    'password' => password_hash($password, PASSWORD_DEFAULT),
                    'role' => 'user',
                    'is_active' => 1,
                ]);
                return $this->response->redirect(site_url('login'));
            }
        }

        $this->call->view('register', ['error' => $error]);
    }

    public function logout()
    {
        $this->session->sess_destroy();
        return $this->response->redirect(site_url('login'));
    }
}