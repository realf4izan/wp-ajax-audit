<?php
/**
 * Plugin Name: Vulnerable Plugin (SAMPLE — DO NOT INSTALL ON A REAL SITE)
 * Description: Tiny fake plugin used to test wp-ajax-audit. Contains one
 *              vulnerable nopriv AJAX handler, one safe AJAX handler, one
 *              open REST route and one protected REST route.
 * Version:     0.1.0
 */

// Vulnerable: nopriv AJAX handler with no authorization check at all.
add_action( 'wp_ajax_nopriv_vp_delete_data', 'vp_delete_data' );

function vp_delete_data() {
    delete_option( 'vp_important_data' );
    wp_send_json_success( 'deleted' );
}

// Safe: logged-in AJAX handler with capability + nonce checks.
add_action( 'wp_ajax_vp_save_settings', 'vp_save_settings' );

function vp_save_settings() {
    check_ajax_referer( 'vp_settings_nonce' );
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( 'forbidden', 403 );
    }
    update_option( 'vp_settings', sanitize_text_field( $_POST['value'] ) );
    wp_send_json_success( 'saved' );
}

// Vulnerable: REST route with no permission_callback — public by default.
add_action( 'rest_api_init', function () {
    register_rest_route( 'vp/v1', '/public-info', array(
        'methods'  => 'GET',
        'callback' => 'vp_get_info',
    ) );
} );

function vp_get_info() {
    return array( 'secret' => get_option( 'vp_important_data' ) );
}

// Safe: REST route with a permission_callback that checks a capability.
add_action( 'rest_api_init', function () {
    register_rest_route( 'vp/v1', '/admin-stats', array(
        'methods'             => 'GET',
        'callback'            => 'vp_get_stats',
        'permission_callback' => 'vp_can_view_stats',
    ) );
} );

function vp_can_view_stats() {
    return current_user_can( 'manage_options' );
}

function vp_get_stats() {
    return array( 'stats' => 'admin only' );
}
