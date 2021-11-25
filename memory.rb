require_relative "addressable"

class Memory < Addressable
    def initialize
        super
        @name = "memory"
    end
end