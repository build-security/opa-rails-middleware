# frozen_string_literal: true

require_relative "policy_decision_point/version"
require_relative "policy_decision_point/pdp"

module PolicyDecisionPoint
  ##
  # Represents an authentication attempt failure.
  class AuthnError < StandardError
    def initialize(e = nil)
      super e
        set_backtrace e.backtrace if e
    end
  end

  ##
  # Represents an authorization attempt failure.
  class AuthzError < StandardError
    def initialize(e = nil)
      super e
        set_backtrace e.backtrace if e
    end
  end
end
