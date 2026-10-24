# name: discourse-email-rate-limiter
# about: Rate limits user creation and password reset emails per destination email address
# version: 1.0.0
# authors: FreeMdict Forum Admin

enabled_site_setting :email_signup_rate_limit_enabled

after_initialize do
  module EmailRateLimiterConstants
    MAX_ATTEMPTS_PER_DAY = 3
    EXPIRATION_SECONDS = 86_400 # 24 hours

    def check_and_apply_email_limit(raw_email, action_name)
      return true unless SiteSetting.email_signup_rate_limit_enabled
      return true if raw_email.blank?

      normalized_email = raw_email.to_s.downcase.strip
      return true unless normalized_email.include?("@")

      email_hash = Digest::SHA256.hexdigest(normalized_email)
      redis_key = "email_#{action_name}_attempts:#{email_hash}"

      current_attempts = Discourse.redis.get(redis_key).to_i

      if current_attempts >= MAX_ATTEMPTS_PER_DAY
        render json: {
          success: false,
          message: "Too many requests for this email address. Please try again tomorrow."
        }, status: 429
        return false
      end

      Discourse.redis.incr(redis_key)
      Discourse.redis.expire(redis_key, EXPIRATION_SECONDS)
      true
    end
  end

  # 1. Intercept User Signups (UsersController#create)
  module SignupRateLimiterExtension
    include EmailRateLimiterConstants

    def create
      if check_and_apply_email_limit(params[:email], "signup")
        super
      end
    end
  end

  # 2. Intercept Password Resets (SessionController#forgot_password)
  module PasswordResetRateLimiterExtension
    include EmailRateLimiterConstants

    def forgot_password
      login_param = params[:login].to_s
      target_email = login_param

      # If the user typed a username instead of an email, look up their email from the database
      unless login_param.include?("@")
        user = User.find_by_username_or_email(login_param)
        target_email = user&.email if user
      end

      if check_and_apply_email_limit(target_email, "password_reset")
        super
      end
    end
  end

  require_dependency "users_controller"
  class ::UsersController
    prepend SignupRateLimiterExtension
  end

  require_dependency "session_controller"
  class ::SessionController
    prepend PasswordResetRateLimiterExtension
  end
end
